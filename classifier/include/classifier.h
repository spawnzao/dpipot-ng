#ifndef CLASSIFIER_H
#define CLASSIFIER_H

#include <ndpi/ndpi_api.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* resolução de timestamp em ms */
#define TICK_RESOLUTION 1000

/* tamanho máximo do buffer de payload recebido do proxy */
#define MAX_PAYLOAD_SIZE (64 * 1024)  /* 64KB */

/* tamanho máximo do flow_id (UUID = 36 chars + null) */
#define FLOW_ID_SIZE 37

/*
 * nDPI_workflow — contexto global do classificador.
 * Um por processo, compartilhado entre todas as conexões.
 */
struct nDPI_workflow {
    /* handle do pcap — NULL neste projeto (não usamos pcap direto) */
    pcap_t *pcap_handle;

    /* engine global do nDPI — inicializado uma vez */
    struct ndpi_detection_module_struct *ndpi_struct;

    /* árvore binária de fluxos ativos, particionada por hash */
    void   **ndpi_flows_active;
    uint64_t max_active_flows;
    uint64_t cur_active_flows;
    uint64_t total_active_flows;

    /* fila de fluxos expirados aguardando liberação */
    void   **ndpi_flows_idle;
    uint64_t max_idle_flows;
    uint64_t cur_idle_flows;
    uint64_t total_idle_flows;

    /* timestamps para controle de idle scan */
    uint64_t last_time;
    uint64_t last_idle_scan_time;

    /* contadores globais */
    uint64_t packets_captured;
    uint64_t packets_processed;
    uint64_t total_l4_data_len;
};

/* inicializa o workflow do nDPI — chamado uma vez no startup */
struct nDPI_workflow *init_workflow(void);

/* libera todos os recursos do workflow */
void free_workflow(struct nDPI_workflow **workflow);

/*
 * Classifica um payload recebido do proxy.
 *
 * O proxy manda bytes brutos da camada TCP (sem header Ethernet/IP).
 * Precisamos construir um pacote sintético para o nDPI processar.
 *
 * Parâmetros:
 *   workflow     — contexto global do nDPI
 *   flow_id      — UUID do fluxo (vem do proxy Go)
 *   src_ip       — IP de origem em network byte order
 *   src_port     — porta de origem
 *   dst_ip       — IP de destino em network byte order
 *   dst_port     — porta de destino
 *   payload      — bytes do payload TCP
 *   payload_len  — tamanho do payload
 *   result_out   — buffer de saída para o resultado (chamador aloca)
 *   result_size  — tamanho do buffer de saída
 *
 * Retorna:
 *   pointer para result_out se OK, NULL em caso de erro.
 */
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
    size_t                result_size
);

/* verifica e expira fluxos ociosos */
void check_for_idle_flows(int dump_all, struct nDPI_workflow *workflow);

#endif /* CLASSIFIER_H */