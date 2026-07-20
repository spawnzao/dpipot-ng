#include <ndpi/ndpi_api.h>
#include <ndpi/ndpi_typedefs.h>

typedef struct ndpi_proto_result {
    uint16_t master_protocol;
    uint16_t app_protocol;
    uint32_t category;
} ndpi_proto_result_t;

extern struct ndpi_detection_module_struct *ndpi_detection_module_initialize(NDPI_PROTOCOL_BITMASK *bitmask);
extern void ndpi_detection_module_exit(struct ndpi_detection_module_struct *ndpi_struct);

extern ndpi_proto_result_t ndpi_packet_processing(struct ndpi_detection_module_struct *ndpi_struct,
                                                   struct ndpi_flow_struct *flow,
                                                   const unsigned char *packet,
                                                   const unsigned short packetlen,
                                                   const uint64_t packet_time_ms);

extern ndpi_proto_result_t ndpi_detection_process_wrapper(struct ndpi_detection_module_struct *,
                                                            struct ndpi_flow_struct *,
                                                            const unsigned char *,
                                                            const unsigned short,
                                                            const uint64_t);

extern void ndpi_flow_setup(struct ndpi_flow_struct *,
                             const uint8_t src_ip[4],
                             const uint8_t dst_ip[4],
                             const uint8_t l4_protocol,
                             const uint16_t src_port,
                             const uint16_t dst_port);

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
extern uint8_t ndpi_flow_get_client_packet_direction(struct ndpi_flow_struct *);
extern uint8_t ndpi_flow_get_packet_direction(struct ndpi_flow_struct *);
extern uint8_t ndpi_flow_get_is_ipv6(struct ndpi_flow_struct *);

extern uint8_t ndpi_extra_dissection_possible(struct ndpi_detection_module_struct *,
                                               struct ndpi_flow_struct *);