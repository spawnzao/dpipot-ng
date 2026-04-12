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

extern uint8_t ndpi_flow_get_setup_packet_direction(struct ndpi_flow_struct *flow) {
    return flow ? flow->setup_packet_direction : 0;
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
    flow->setup_packet_direction = 1;
    
    flow->saddr = (src_ip[0] << 24) | (src_ip[1] << 16) | (src_ip[2] << 8) | src_ip[3];
    flow->daddr = (dst_ip[0] << 24) | (dst_ip[1] << 16) | (dst_ip[2] << 8) | dst_ip[3];
    flow->sport = src_port;
    flow->dport = dst_port;
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
    NDPI_BITMASK_RESET(*bitmask);
}

extern void ndpi_protocol_bitmask_set_all(NDPI_PROTOCOL_BITMASK *bitmask) {
    NDPI_BITMASK_SET_ALL(*bitmask);
}

extern struct ndpi_detection_module_struct *ndpi_detection_module_create(NDPI_PROTOCOL_BITMASK *bitmask) {
    return ndpi_init_detection_module(0);
}

extern void ndpi_detection_module_destroy(struct ndpi_detection_module_struct *ndpi_struct) {
    if (ndpi_struct) {
        ndpi_exit_detection_module(ndpi_struct);
    }
}

extern ndpi_proto_defaults_t *ndpi_proto_defaults_get(struct ndpi_detection_module_struct *ndpi_struct,
                                                      bool *is_clear_text_proto, bool *is_app_protocol)
{
    ndpi_proto_defaults_t *pd = ndpi_get_proto_defaults(ndpi_struct);

    for (uint32_t i = 0; i < NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_CUSTOM_PROTOCOLS; i++)
    {
        is_clear_text_proto[i] = pd[i].isClearTextProto;
        is_app_protocol[i] = false;
    }

    return pd;
}

extern uint8_t ndpi_extra_dissection_possible(struct ndpi_detection_module_struct *ndpi_struct,
                                              struct ndpi_flow_struct *flow) {
    return ndpi_extra_dissection_possible(ndpi_struct, flow) ? 1 : 0;
}

extern ndpi_proto_result_t ndpi_classify_packet(struct ndpi_detection_module_struct *ndpi_struct,
                                                 struct ndpi_flow_struct *flow,
                                                 const unsigned char *packet,
                                                 const unsigned short packetlen,
                                                 const uint8_t *src_mac,
                                                 const uint8_t *dst_mac,
                                                 const uint8_t packet_direction,
                                                 const uint16_t src_port,
                                                 const uint16_t dst_port,
                                                 const uint64_t packet_time_ms)
{
    ndpi_proto_result_t result = {0, 0, 0};
    
    if (!ndpi_struct || !flow || !packet) {
        return result;
    }
    
    struct ndpi_proto proto = ndpi_detection_process_packet(ndpi_struct, flow, packet, packetlen, packet_time_ms);
    
    result.master_protocol = proto.master_protocol;
    result.app_protocol = proto.app_protocol;
    result.category = proto.category;
    
    return result;
}

extern ndpi_proto_result_t ndpi_detection_process_wrapper(struct ndpi_detection_module_struct *ndpi_struct,
                                                           struct ndpi_flow_struct *flow,
                                                           const unsigned char *packet,
                                                           const unsigned short packetlen,
                                                           const uint64_t packet_time_ms)
{
    return ndpi_classify_packet(ndpi_struct, flow, packet, packetlen, NULL, NULL, 1, 0, 0, packet_time_ms);
}