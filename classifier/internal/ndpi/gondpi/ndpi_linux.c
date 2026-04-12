#include "ndpi_linux.h"

extern void ndpi_protocol_bitmask_add(NDPI_PROTOCOL_BITMASK *bitmask, uint16_t proto)
{
    NDPI_BITMASK_ADD(*bitmask, proto);
}

extern void ndpi_protocol_bitmask_del(NDPI_PROTOCOL_BITMASK *bitmask, uint16_t proto)
{
    NDPI_BITMASK_DEL(*bitmask, proto);
}

extern bool ndpi_protocol_bitmask_is_set(NDPI_PROTOCOL_BITMASK *bitmask, uint16_t proto)
{
    return NDPI_ISSET(bitmask, proto);
}

extern void ndpi_protocol_bitmask_reset(NDPI_PROTOCOL_BITMASK *bitmask)
{
    NDPI_BITMASK_RESET(*bitmask);
}

extern void ndpi_protocol_bitmask_set_all(NDPI_PROTOCOL_BITMASK *bitmask)
{
    NDPI_BITMASK_SET_ALL(*bitmask);
}

extern struct ndpi_flow_struct *ndpi_flow_struct_malloc()
{
    struct ndpi_flow_struct *newflow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);

    if (newflow != NULL)
    {
        memset(newflow, 0, SIZEOF_FLOW_STRUCT);
    }

    return newflow;
}

extern void ndpi_flow_struct_free(struct ndpi_flow_struct *flow)
{
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

extern struct ndpi_detection_module_struct *ndpi_detection_module_create(NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
    set_ndpi_malloc(malloc);
    set_ndpi_free(free);

    struct ndpi_detection_module_struct *ndpi_struct = ndpi_init_detection_module(0);
    if (ndpi_struct == NULL)
    {
        return NULL;
    }

    ndpi_set_protocol_detection_bitmask2(ndpi_struct, detection_bitmask);

    ndpi_finalize_initialization(ndpi_struct);

    return ndpi_struct;
}

extern void ndpi_detection_module_destroy(struct ndpi_detection_module_struct *ndpi_struct)
{
    ndpi_exit_detection_module(ndpi_struct);
}

extern ndpi_proto_defaults_t *ndpi_proto_defaults_get(struct ndpi_detection_module_struct *ndpi_struct,
                                                      bool *is_clear_text_proto, bool *is_app_protocol)
{
    ndpi_proto_defaults_t *pd = ndpi_get_proto_defaults(ndpi_struct);

    for (uint32_t i = 0; i < NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS; i++)
    {
        is_clear_text_proto[i] = pd[i].isClearTextProto;
        is_app_protocol[i] = false;
    }

    return pd;
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

extern ndpi_proto_result_t ndpi_classify_packet(struct ndpi_detection_module_struct *ndpi_struct,
                                                  struct ndpi_flow_struct *flow,
                                                  const unsigned char *packet,
                                                  const unsigned short packetlen,
                                                  const uint8_t *src_ip,
                                                  const uint8_t *dst_ip,
                                                  const uint8_t l4_protocol,
                                                  const uint16_t src_port,
                                                  const uint16_t dst_port,
                                                  const uint64_t packet_time_ms)
{
    ndpi_proto_result_t result = {0, 0, 0};
    
    ndpi_flow_setup(flow, src_ip, dst_ip, l4_protocol, src_port, dst_port);
    
    struct ndpi_proto proto = ndpi_detection_process_packet(ndpi_struct, flow, packet, packetlen, packet_time_ms);

    result.master_protocol = proto.master_protocol;
    result.app_protocol = proto.app_protocol;
    result.category = proto.category;

    return result;
}

extern struct ndpi_proto ndpi_detection_giveup_wrapper(struct ndpi_detection_module_struct *ndpi_struct,
                                                       struct ndpi_flow_struct *flow,
                                                       uint8_t enable_guess,
                                                       uint8_t protocol_was_guessed)
{
    return ndpi_detection_giveup(ndpi_struct, flow, enable_guess, &protocol_was_guessed);
}

extern uint8_t ndpi_extra_dissection_possible(struct ndpi_detection_module_struct *ndpi_struct,
                                               struct ndpi_flow_struct *flow)
{
    return 1;
}

extern ndpi_proto_result_t ndpi_detection_process_wrapper(struct ndpi_detection_module_struct *ndpi_struct,
                                                            struct ndpi_flow_struct *flow,
                                                            const unsigned char *packet,
                                                            const unsigned short packetlen,
                                                            const uint64_t packet_time_ms)
{
    ndpi_proto_result_t result = {0, 0, 0};
    
    struct ndpi_proto proto = ndpi_detection_process_packet(ndpi_struct, flow, packet, packetlen, packet_time_ms);

    result.master_protocol = proto.master_protocol;
    result.app_protocol = proto.app_protocol;
    result.category = proto.category;

    return result;
}