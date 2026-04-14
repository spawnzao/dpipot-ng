#include "ndpi_linux.h"
#include <ndpi/ndpi_api.h>
#include <ndpi/ndpi_typedefs.h>
#include <string.h>
#include <stdio.h>

#define NDPI_MAX_CUSTOM_PROTOCOLS 256

extern struct ndpi_flow_struct *ndpi_flow_struct_malloc() {
    return ndpi_flow_malloc(sizeof(struct ndpi_flow_struct));
}

extern void ndpi_flow_struct_free(struct ndpi_flow_struct *flow) {
    if (flow) {
        ndpi_flow_free(flow);
    }
}

extern uint8_t ndpi_flow_get_protocol_id_already_guessed(struct ndpi_flow_struct *flow) {
    return flow ? flow->protocol_id_already_guessed : 0;
}

extern uint8_t ndpi_flow_get_host_already_guessed(struct ndpi_flow_struct *flow) {
    return flow && flow->host_server_name[0] != '\0';
}

extern uint8_t ndpi_flow_get_fail_with_unknown(struct ndpi_flow_struct *flow) {
    return flow ? flow->fail_with_unknown : 0;
}

extern uint8_t ndpi_flow_get_init_finished(struct ndpi_flow_struct *flow) {
    return flow ? flow->init_finished : 0;
}

extern uint8_t ndpi_flow_get_client_packet_direction(struct ndpi_flow_struct *flow) {
    return flow ? flow->client_packet_direction : 0;
}

extern uint8_t ndpi_flow_get_packet_direction(struct ndpi_flow_struct *flow) {
    return flow ? flow->packet_direction : 0;
}

extern uint8_t ndpi_flow_get_is_ipv6(struct ndpi_flow_struct *flow) {
    return flow ? flow->is_ipv6 : 0;
}

extern void ndpi_flow_setup(struct ndpi_flow_struct *flow,
                             const uint8_t src_ip[4],
                             const uint8_t dst_ip[4],
                             const uint8_t l4_protocol,
                             const uint16_t src_port,
                             const uint16_t dst_port)
{
    memset(flow, 0, sizeof(struct ndpi_flow_struct));
    
    flow->l4_proto = l4_protocol;
    flow->packet_direction = 1;
    flow->client_packet_direction = 1;
    flow->c_port = src_port;
    flow->s_port = dst_port;
    
    flow->c_address.v4 = (src_ip[0] << 24) | (src_ip[1] << 16) | (src_ip[2] << 8) | src_ip[3];
    flow->s_address.v4 = (dst_ip[0] << 24) | (dst_ip[1] << 16) | (src_ip[2] << 8) | dst_ip[3];
}

extern void ndpi_protocol_bitmask_add(NDPI_PROTOCOL_BITMASK *bitmask, uint16_t protocol_id) {
    NDPI_BITMASK_ADD(*bitmask, protocol_id);
}

extern void ndpi_protocol_bitmask_del(NDPI_PROTOCOL_BITMASK *bitmask, uint16_t protocol_id) {
    NDPI_BITMASK_DEL(*bitmask, protocol_id);
}

extern bool ndpi_protocol_bitmask_is_set(NDPI_PROTOCOL_BITMASK *bitmask, uint16_t protocol_id) {
    return NDPI_ISSET(bitmask, protocol_id) ? true : false;
}

extern void ndpi_protocol_bitmask_reset(NDPI_PROTOCOL_BITMASK *bitmask) {
    NDPI_BITMASK_RESET(bitmask);
}

extern void ndpi_protocol_bitmask_set_all(NDPI_PROTOCOL_BITMASK *bitmask) {
    NDPI_BITMASK_SET_ALL(*bitmask);
}

extern struct ndpi_detection_module_struct *ndpi_detection_module_initialize(NDPI_PROTOCOL_BITMASK *bitmask) {
    struct ndpi_global_context *g_ctx = ndpi_global_init();
    if (!g_ctx) {
        return NULL;
    }
    
    struct ndpi_detection_module_struct *ndpi_struct = ndpi_init_detection_module(g_ctx);
    if (ndpi_struct) {
        ndpi_finalize_initialization(ndpi_struct);
    }
    return ndpi_struct;
}

extern void ndpi_detection_module_exit(struct ndpi_detection_module_struct *ndpi_struct) {
    if (ndpi_struct) {
        ndpi_exit_detection_module(ndpi_struct);
    }
}

extern ndpi_proto_result_t ndpi_packet_processing(struct ndpi_detection_module_struct *ndpi_struct,
                                                  struct ndpi_flow_struct *flow,
                                                  const unsigned char *packet,
                                                  const unsigned short packetlen,
                                                  const uint64_t packet_time_ms)
{
    ndpi_proto_result_t result = {0, 0, 0};
    
    if (!ndpi_struct || !flow || !packet) {
        return result;
    }
    
    struct ndpi_proto proto = ndpi_detection_process_packet(ndpi_struct, flow, packet, packetlen, packet_time_ms, NULL);
    
    result.master_protocol = proto.proto.master_protocol;
    result.app_protocol = proto.proto.app_protocol;
    result.category = (uint32_t)proto.category;
    
    return result;
}

extern ndpi_proto_result_t ndpi_detection_process_wrapper(struct ndpi_detection_module_struct *ndpi_struct,
                                                          struct ndpi_flow_struct *flow,
                                                          const unsigned char *packet,
                                                          const unsigned short packetlen,
                                                          const uint64_t packet_time_ms)
{
    return ndpi_packet_processing(ndpi_struct, flow, packet, packetlen, packet_time_ms);
}

extern uint8_t ndpi_extra_dissection_possible(struct ndpi_detection_module_struct *ndpi_struct,
                                               struct ndpi_flow_struct *flow) {
    return ndpi_extra_dissection_possible(ndpi_struct, flow) ? 1 : 0;
}
