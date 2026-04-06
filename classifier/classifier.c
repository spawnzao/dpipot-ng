#include "classifier.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

#define MAX_FLOW_ROOTS_PER_THREAD  512
#define MAX_IDLE_FLOWS_PER_THREAD   64
#define IDLE_SCAN_PERIOD          1000
#define MAX_IDLE_TIME_TCP         5000
#define MAX_IDLE_TIME_UDP         1000

enum nDPI_l3_type { L3_IP, L3_IP6 };

struct nDPI_flow_info {
    uint32_t flow_id;
    char     flow_uuid[FLOW_ID_SIZE];
    unsigned long long packets_processed;
    uint64_t first_seen;
    uint64_t last_seen;
    uint64_t hashval;
    enum nDPI_l3_type l3_type;
    union {
        struct { uint32_t src; uint32_t dst; } v4;
        struct { uint64_t src[2]; uint64_t dst[2]; } v6;
    } ip_tuple;
    unsigned long long total_l4_data_len;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t detection_completed : 1;
    uint8_t flow_fin_ack_seen   : 1;
    uint8_t flow_ack_seen       : 1;
    uint8_t reserved            : 5;
    uint8_t l4_protocol;
    struct ndpi_proto detected_l7_protocol;
    struct ndpi_flow_struct *ndpi_flow;
};

static uint32_t g_flow_id = 0;

static void ndpi_flow_info_freer(void *const node)
{
    struct nDPI_flow_info *const flow = (struct nDPI_flow_info *)node;
    if (flow->ndpi_flow)
        ndpi_flow_free(flow->ndpi_flow);
    ndpi_free(flow);
}

static int ip_tuples_equal(const struct nDPI_flow_info *A,
                           const struct nDPI_flow_info *B)
{
    if (A->l3_type == L3_IP && B->l3_type == L3_IP) {
        return A->ip_tuple.v4.src == B->ip_tuple.v4.src &&
               A->ip_tuple.v4.dst == B->ip_tuple.v4.dst;
    }
    return 0;
}

static int ip_tuples_compare(const struct nDPI_flow_info *A,
                             const struct nDPI_flow_info *B)
{
    if (A->l3_type == L3_IP && B->l3_type == L3_IP) {
        if (A->ip_tuple.v4.src < B->ip_tuple.v4.src) return -1;
        if (A->ip_tuple.v4.src > B->ip_tuple.v4.src) return  1;
        if (A->ip_tuple.v4.dst < B->ip_tuple.v4.dst) return -1;
        if (A->ip_tuple.v4.dst > B->ip_tuple.v4.dst) return  1;
    }
    if (A->src_port < B->src_port) return -1;
    if (A->src_port > B->src_port) return  1;
    if (A->dst_port < B->dst_port) return -1;
    if (A->dst_port > B->dst_port) return  1;
    return 0;
}

static int ndpi_workflow_node_cmp(const void *A, const void *B)
{
    const struct nDPI_flow_info *a = (const struct nDPI_flow_info *)A;
    const struct nDPI_flow_info *b = (const struct nDPI_flow_info *)B;
    if (a->hashval < b->hashval) return -1;
    if (a->hashval > b->hashval) return  1;
    if (a->l4_protocol < b->l4_protocol) return -1;
    if (a->l4_protocol > b->l4_protocol) return  1;
    if (ip_tuples_equal(a, b) &&
        a->src_port == b->src_port &&
        a->dst_port == b->dst_port)
        return 0;
    return ip_tuples_compare(a, b);
}

static void ndpi_idle_scan_walker(const void *A, ndpi_VISIT which,
                                  int depth, void *user_data)
{
    struct nDPI_workflow  *workflow = (struct nDPI_workflow *)user_data;
    struct nDPI_flow_info *flow     = *(struct nDPI_flow_info **)A;
    (void)depth;
    if (!workflow || !flow) return;
    if (workflow->cur_idle_flows == MAX_IDLE_FLOWS_PER_THREAD) return;
    if (which == ndpi_preorder || which == ndpi_leaf) {
        int tcp_expired = (flow->l4_protocol == IPPROTO_TCP &&
                           flow->last_seen + MAX_IDLE_TIME_TCP < workflow->last_time);
        int udp_expired = (flow->l4_protocol != IPPROTO_TCP &&
                           flow->last_seen + MAX_IDLE_TIME_UDP < workflow->last_time);
        int fin_seen    = (flow->flow_fin_ack_seen == 1 && flow->flow_ack_seen == 1);
        if (tcp_expired || udp_expired || fin_seen) {
            if (!flow->detection_completed && flow->ndpi_flow) {
                uint8_t guessed = 0;
                flow->detected_l7_protocol =
                    ndpi_detection_giveup(workflow->ndpi_struct, flow->ndpi_flow, &guessed);
                flow->detection_completed = 1;
            }
            workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow;
            workflow->total_idle_flows++;
        }
    }
}

void check_for_idle_flows(int dump_all, struct nDPI_workflow *workflow)
{
    if (dump_all) workflow->last_time = UINT32_MAX;
    if (workflow->last_idle_scan_time + IDLE_SCAN_PERIOD < workflow->last_time) {
        for (size_t i = 0; i < workflow->max_active_flows; i++) {
            ndpi_twalk(workflow->ndpi_flows_active[i], ndpi_idle_scan_walker, workflow);
            while (workflow->cur_idle_flows > 0) {
                struct nDPI_flow_info *f =
                    (struct nDPI_flow_info *)
                    workflow->ndpi_flows_idle[--workflow->cur_idle_flows];
                ndpi_tdelete(f, &workflow->ndpi_flows_active[i], ndpi_workflow_node_cmp);
                ndpi_flow_info_freer(f);
                workflow->cur_active_flows--;
            }
        }
        workflow->last_idle_scan_time = workflow->last_time;
    }
}

struct nDPI_workflow *init_workflow(void)
{
    struct nDPI_workflow *w = (struct nDPI_workflow *)ndpi_calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->pcap_handle = NULL;
    w->ndpi_struct = ndpi_init_detection_module(0);
    if (!w->ndpi_struct) { ndpi_free(w); return NULL; }
    ndpi_finalize_initialization(w->ndpi_struct);
    w->max_active_flows  = MAX_FLOW_ROOTS_PER_THREAD;
    w->ndpi_flows_active = (void **)ndpi_calloc(w->max_active_flows, sizeof(void *));
    if (!w->ndpi_flows_active) goto err;
    w->max_idle_flows  = MAX_IDLE_FLOWS_PER_THREAD;
    w->ndpi_flows_idle = (void **)ndpi_calloc(w->max_idle_flows, sizeof(void *));
    if (!w->ndpi_flows_idle) goto err;
    
    fprintf(stderr, "[classifier] nDPI inicializado\n");
    return w;
err:
    free_workflow(&w);
    return NULL;
}

void free_workflow(struct nDPI_workflow **workflow)
{
    struct nDPI_workflow *w = *workflow;
    if (!w) return;
    check_for_idle_flows(1, w);
    if (w->ndpi_struct) ndpi_exit_detection_module(w->ndpi_struct);
    if (w->ndpi_flows_active) {
        for (size_t i = 0; i < w->max_active_flows; i++)
            ndpi_tdestroy(w->ndpi_flows_active[i], ndpi_flow_info_freer);
        ndpi_free(w->ndpi_flows_active);
    }
    if (w->ndpi_flows_idle) ndpi_free(w->ndpi_flows_idle);
    ndpi_free(w);
    *workflow = NULL;
}

struct synthetic_ipv4 {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct synthetic_tcp {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  data_off;
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

const char *classify_payload(
    struct nDPI_workflow *workflow,
    const char           *flow_id,
    uint32_t              src_ip,
    uint16_t              src_port,
    uint32_t              dst_ip,
    uint16_t              dst_port,
    const uint8_t        *payload,
    uint16_t              payload_len,
    char                 *result_out,
    size_t                result_size)
{
    if (!workflow || !payload || payload_len == 0 || !result_out) return "Unknown";

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t time_ms = (uint64_t)tv.tv_sec * TICK_RESOLUTION
                     + (uint64_t)tv.tv_usec / (1000000 / TICK_RESOLUTION);
    workflow->last_time = time_ms;

    size_t pkt_size = sizeof(struct synthetic_ipv4)
                    + sizeof(struct synthetic_tcp)
                    + payload_len;
    uint8_t *pkt = (uint8_t *)malloc(pkt_size);
    if (!pkt) return "Unknown";

    struct synthetic_ipv4 *ip = (struct synthetic_ipv4 *)pkt;
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl  = 0x45;
    ip->tot_len  = htons((uint16_t)pkt_size);
    ip->ttl      = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr    = src_ip;
    ip->daddr    = dst_ip;

    struct synthetic_tcp *tcp =
        (struct synthetic_tcp *)(pkt + sizeof(struct synthetic_ipv4));
    memset(tcp, 0, sizeof(*tcp));
    tcp->source   = htons(src_port);
    tcp->dest     = htons(dst_port);
    tcp->data_off = 0x50;
    tcp->flags    = 0x18;
    tcp->window   = htons(65535);

    memcpy(pkt + sizeof(struct synthetic_ipv4) + sizeof(struct synthetic_tcp),
           payload, payload_len);

    struct nDPI_flow_info flow_key = {0};
    flow_key.l3_type     = L3_IP;
    flow_key.l4_protocol = IPPROTO_TCP;
    flow_key.ip_tuple.v4.src = src_ip;
    flow_key.ip_tuple.v4.dst = dst_ip;
    flow_key.src_port    = src_port;
    flow_key.dst_port    = dst_port;

    if (ndpi_flowv4_flow_hash(IPPROTO_TCP, src_ip, dst_ip,
                              src_port, dst_port, 0, 0,
                              (uint8_t *)&flow_key.hashval,
                              sizeof(flow_key.hashval)) != 0)
        flow_key.hashval = (uint64_t)src_ip + dst_ip + src_port + dst_port;

    size_t bucket = flow_key.hashval % workflow->max_active_flows;
    void *tree_result = ndpi_tfind(&flow_key,
                                   &workflow->ndpi_flows_active[bucket],
                                   ndpi_workflow_node_cmp);

    if (!tree_result) {
        struct nDPI_flow_info rev = flow_key;
        rev.ip_tuple.v4.src = dst_ip;
        rev.ip_tuple.v4.dst = src_ip;
        rev.src_port = dst_port;
        rev.dst_port = src_port;
        if (ndpi_flowv4_flow_hash(IPPROTO_TCP, dst_ip, src_ip,
                                  dst_port, src_port, 0, 0,
                                  (uint8_t *)&rev.hashval,
                                  sizeof(rev.hashval)) != 0)
            rev.hashval = (uint64_t)dst_ip + src_ip + dst_port + src_port;
        size_t rev_bucket = rev.hashval % workflow->max_active_flows;
        tree_result = ndpi_tfind(&rev,
                                 &workflow->ndpi_flows_active[rev_bucket],
                                 ndpi_workflow_node_cmp);
    }

    struct nDPI_flow_info *flow_to_process = NULL;

    if (!tree_result) {
        flow_to_process = (struct nDPI_flow_info *)ndpi_malloc(sizeof(*flow_to_process));
        if (!flow_to_process) { free(pkt); return "Unknown"; }
        memcpy(flow_to_process, &flow_key, sizeof(*flow_to_process));
        flow_to_process->flow_id = g_flow_id++;
        strncpy(flow_to_process->flow_uuid, flow_id, FLOW_ID_SIZE - 1);
        flow_to_process->first_seen = time_ms;
        flow_to_process->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
        if (!flow_to_process->ndpi_flow) {
            ndpi_free(flow_to_process); free(pkt); return "Unknown";
        }
        memset(flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
        if (!ndpi_tsearch(flow_to_process,
                          &workflow->ndpi_flows_active[bucket],
                          ndpi_workflow_node_cmp)) {
            ndpi_flow_info_freer(flow_to_process);
            free(pkt);
            return "Unknown";
        }
        workflow->cur_active_flows++;
        workflow->total_active_flows++;
    } else {
        flow_to_process = *(struct nDPI_flow_info **)tree_result;
    }

    flow_to_process->packets_processed++;
    flow_to_process->total_l4_data_len += payload_len;
    flow_to_process->last_seen = time_ms;

    flow_to_process->detected_l7_protocol =
        ndpi_detection_process_packet(
            workflow->ndpi_struct,
            flow_to_process->ndpi_flow,
            (const unsigned char *)pkt,
            (uint16_t)pkt_size,
            time_ms,
            NULL);

    free(pkt);

    // nDPI 4.12: giveup se necessário
    if (!flow_to_process->detection_completed && flow_to_process->ndpi_flow) {
        uint8_t guessed = 0;
        flow_to_process->detected_l7_protocol =
            ndpi_detection_giveup(workflow->ndpi_struct,
                                  flow_to_process->ndpi_flow,
                                  &guessed);
        flow_to_process->detection_completed = 1;
    }

    struct ndpi_proto proto = flow_to_process->detected_l7_protocol;
    uint16_t best = NDPI_PROTOCOL_UNKNOWN;
    
    if (proto.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN)
        best = proto.proto.master_protocol;
    else if (proto.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
        best = proto.proto.app_protocol;

    if (best != NDPI_PROTOCOL_UNKNOWN) {
        const char *proto_name = ndpi_get_proto_name(workflow->ndpi_struct, best);
        snprintf(result_out, result_size, "%s", proto_name);
    } else {
        snprintf(result_out, result_size, "Unknown");
    }

    check_for_idle_flows(0, workflow);
    return result_out;
}