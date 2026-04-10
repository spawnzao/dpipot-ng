#include <ndpi/ndpi_api.h>
#include <ndpi/ndpi_typedefs.h>
#include <string.h>
#include <stdlib.h>

typedef struct ndpi_proto_result {
    uint16_t master_protocol;
    uint16_t app_protocol;
    uint8_t category;
} ndpi_proto_result_t;

extern void ndpi_protocol_bitmask_add(NDPI_PROTOCOL_BITMASK *bitmask, uint16_t proto) {
    NDPI_BITMASK_ADD(*bitmask, proto);
}

extern void ndpi_protocol_bitmask_del(NDPI_PROTOCOL_BITMASK *bitmask, uint16_t proto) {
    NDPI_BITMASK_DEL(*bitmask, proto);
}

extern bool ndpi_protocol_bitmask_is_set(NDPI_PROTOCOL_BITMASK *bitmask, uint16_t proto) {
    return NDPI_ISSET(bitmask, proto);
}

extern void ndpi_protocol_bitmask_reset(NDPI_PROTOCOL_BITMASK *bitmask) {
    NDPI_BITMASK_RESET(*bitmask);
}

extern void ndpi_protocol_bitmask_set_all(NDPI_PROTOCOL_BITMASK *bitmask) {
    NDPI_BITMASK_SET_ALL(*bitmask);
}

extern struct ndpi_flow_struct *ndpi_flow_struct_malloc() {
    struct ndpi_flow_struct *newflow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (newflow != NULL) {
        memset(newflow, 0, SIZEOF_FLOW_STRUCT);
    }
    return newflow;
}

extern void ndpi_flow_struct_free(struct ndpi_flow_struct *flow) {
    ndpi_free_flow(flow);
}

extern uint8_t ndpi_flow_get_protocol_id_already_guessed(struct ndpi_flow_struct *flow) {
    return (flow->protocol_id_already_guessed & 0x01);
}

extern uint8_t ndpi_flow_get_host_already_guessed(struct ndpi_flow_struct *flow) {
    return (flow->protocol_id_already_guessed >> 1) & 0x01;
}

extern uint8_t ndpi_flow_get_fail_with_unknown(struct ndpi_flow_struct *flow) {
    return (flow->protocol_id_already_guessed >> 2) & 0x01;
}

extern uint8_t ndpi_flow_get_init_finished(struct ndpi_flow_struct *flow) {
    return (flow->protocol_id_already_guessed >> 3) & 0x01;
}

extern uint8_t ndpi_flow_get_setup_packet_direction(struct ndpi_flow_struct *flow) {
    return flow->setup_packet_direction;
}

extern uint8_t ndpi_flow_get_packet_direction(struct ndpi_flow_struct *flow) {
    return flow->packet_direction;
}

extern uint8_t ndpi_flow_get_is_ipv6(struct ndpi_flow_struct *flow) {
    return flow->is_ipv6;
}

extern struct ndpi_detection_module_struct *ndpi_detection_module_create(NDPI_PROTOCOL_BITMASK *detection_bitmask) {
    set_ndpi_malloc(malloc);
    set_ndpi_free(free);

    struct ndpi_detection_module_struct *ndpi_struct = ndpi_init_detection_module(0);
    if (ndpi_struct == NULL) {
        return NULL;
    }

    ndpi_set_protocol_detection_bitmask2(ndpi_struct, detection_bitmask);
    ndpi_finalize_initialization(ndpi_struct);

    return ndpi_struct;
}

extern void ndpi_detection_module_destroy(struct ndpi_detection_module_struct *ndpi_struct) {
    ndpi_exit_detection_module(ndpi_struct);
}

extern void ndpi_flow_setup(struct ndpi_flow_struct *flow,
                             const uint8_t src_ip[4],
                             const uint8_t dst_ip[4],
                             const uint8_t l4_protocol,
                             const uint16_t src_port,
                             const uint16_t dst_port) {
    memset(flow, 0, sizeof(struct ndpi_flow_struct));
    
    flow->l4_proto = l4_protocol;
    flow->setup_packet_direction = 1;
    flow->packet_direction = 1;
    
    flow->saddr = (src_ip[0] << 24) | (src_ip[1] << 16) | (src_ip[2] << 8) | src_ip[3];
    flow->daddr = (dst_ip[0] << 24) | (dst_ip[1] << 16) | (dst_ip[2] << 8) | dst_ip[3];
    flow->sport = src_port;
    flow->dport = dst_port;
}

extern ndpi_proto_result_t ndpi_detection_process_wrapper(struct ndpi_detection_module_struct *ndpi_struct,
                                                            struct ndpi_flow_struct *flow,
                                                            const unsigned char *packet,
                                                            const unsigned short packetlen,
                                                            const uint64_t packet_time_ms) {
    ndpi_proto_result_t result = {0, 0, 0};
    
    struct ndpi_proto proto = ndpi_detection_process_packet(ndpi_struct, flow, packet, packetlen, packet_time_ms);

    result.master_protocol = proto.master_protocol;
    result.app_protocol = proto.app_protocol;
    result.category = proto.category;

    return result;
}

extern uint8_t ndpi_extra_dissection_possible(struct ndpi_detection_module_struct *ndpi_struct,
                                               struct ndpi_flow_struct *flow) {
    return 1;
}