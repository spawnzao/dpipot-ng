#include <ndpi/ndpi_api.h>
#include <ndpi/ndpi_typedefs.h>

extern void ndpi_protocol_bitmask_add(NDPI_PROTOCOL_BITMASK *, uint16_t);
extern void ndpi_protocol_bitmask_del(NDPI_PROTOCOL_BITMASK *, uint16_t);
extern bool ndpi_protocol_bitmask_is_set(NDPI_PROTOCOL_BITMASK *, uint16_t);
extern void ndpi_protocol_bitmask_reset(NDPI_PROTOCOL_BITMASK *);
extern void ndpi_protocol_bitmask_set_all(NDPI_PROTOCOL_BITMASK *);

extern struct ndpi_flow_struct *ndpi_flow_struct_malloc();
extern void ndpi_flow_struct_free(struct ndpi_flow_struct *);
extern uint8_t ndpi_flow_get_protocol_id_already_guessed(struct ndpi_flow_struct *);
extern uint8_t ndpi_flow_get_host_already_guessed(struct ndpi_flow_struct *);
extern uint8_t ndpi_flow_get_fail_with_unknown(struct ndpi_flow_struct *);
extern uint8_t ndpi_flow_get_init_finished(struct ndpi_flow_struct *);
extern uint8_t ndpi_flow_get_setup_packet_direction(struct ndpi_flow_struct *);
extern uint8_t ndpi_flow_get_packet_direction(struct ndpi_flow_struct *);
extern uint8_t ndpi_flow_get_is_ipv6(struct ndpi_flow_struct *);

extern struct ndpi_global_context *ndpi_global_context_create();
extern void ndpi_global_context_destroy(struct ndpi_global_context *);
extern struct ndpi_detection_module_struct *ndpi_detection_module_create(struct ndpi_global_context *, NDPI_PROTOCOL_BITMASK *);
extern void ndpi_detection_module_destroy(struct ndpi_detection_module_struct *);
extern ndpi_proto_defaults_t *ndpi_proto_defaults_get(struct ndpi_detection_module_struct *, bool *, bool *);
extern struct ndpi_proto ndpi_packet_processing(struct ndpi_detection_module_struct *,
                                                struct ndpi_flow_struct *,
                                                const unsigned char *,
                                                const unsigned short,
                                                const u_int64_t);
extern uint8_t ndpi_extra_dissection_possible(struct ndpi_detection_module_struct *,
                                               struct ndpi_flow_struct *);