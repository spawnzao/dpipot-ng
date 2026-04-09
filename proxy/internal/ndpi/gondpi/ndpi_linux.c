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
    return flow->client_packet_direction;
}

extern uint8_t ndpi_flow_get_packet_direction(struct ndpi_flow_struct *flow) {
    return flow->packet_direction;
}

extern uint8_t ndpi_flow_get_is_ipv6(struct ndpi_flow_struct *flow) {
    return flow->is_ipv6;
}

extern struct ndpi_global_context *ndpi_global_context_create()
{
    return ndpi_global_init();
}

extern void ndpi_global_context_destroy(struct ndpi_global_context *g_ctx)
{
    ndpi_global_deinit(g_ctx);
}

extern struct ndpi_detection_module_struct *ndpi_detection_module_create(struct ndpi_global_context *g_ctx, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
    set_ndpi_malloc(malloc);
    set_ndpi_free(free);

    struct ndpi_detection_module_struct *ndpi_struct = ndpi_init_detection_module(g_ctx);
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
        is_app_protocol[i] = pd[i].isAppProtocol;
    }

    return pd;
}

extern struct ndpi_proto ndpi_packet_processing(struct ndpi_detection_module_struct *ndpi_struct,
                                                struct ndpi_flow_struct *flow,
                                                const unsigned char *packet,
                                                const unsigned short packetlen,
                                                const u_int64_t packet_time_ms)
{
    struct ndpi_proto proto = ndpi_detection_process_packet(ndpi_struct, flow, packet, packetlen, packet_time_ms, NULL);

    return proto;
}

extern struct ndpi_proto ndpi_detection_giveup_wrapper(struct ndpi_detection_module_struct *ndpi_struct,
                                                       struct ndpi_flow_struct *flow,
                                                       uint8_t *protocol_was_guessed)
{
    return ndpi_detection_giveup(ndpi_struct, flow, protocol_was_guessed);
}

extern uint8_t ndpi_extra_dissection_possible(struct ndpi_detection_module_struct *ndpi_struct,
                                               struct ndpi_flow_struct *flow)
{
    return ndpi_extra_dissection_possible(ndpi_struct, flow);
}