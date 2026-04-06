#include "classifier.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* -------------------------------------------------------------------
 * Protocolo do Unix socket (deve ser espelho do ndpi/client.go):
 *
 *  Proxy → Classifier (request):
 *    [36 bytes: flow_id UUID]
 *    [1 byte: '\n']
 *    [4 bytes: payload_len big-endian]
 *    [4 bytes: src_ip network byte order]
 *    [4 bytes: dst_ip network byte order]
 *    [2 bytes: src_port big-endian]
 *    [2 bytes: dst_port big-endian]
 *    [payload_len bytes: payload TCP]
 *
 *  Classifier → Proxy (response):
 *    "HTTP\n" ou "SSH\n" ou "Unknown\n" etc.
 * ------------------------------------------------------------------- */

#define SOCKET_PATH_DEFAULT  "/var/run/dpipot/ndpi.sock"
#define BACKLOG              128
#define RECV_TIMEOUT_SEC     2

/* workflow global — inicializado uma vez, usado por todas as threads */
static struct nDPI_workflow *g_workflow = NULL;

/* mutex para proteger o workflow (nDPI não é thread-safe por fluxo) */
static pthread_mutex_t g_workflow_mutex = PTHREAD_MUTEX_INITIALIZER;

/* flag de shutdown */
static volatile int g_running = 1;

/* -------------------------------------------------------------------
 * leitura confiável — lê exatamente n bytes do socket
 * ------------------------------------------------------------------- */
static int recv_all(int fd, void *buf, size_t n)
{
    size_t received = 0;
    while (received < n) {
        ssize_t r = recv(fd, (char *)buf + received, n - received, 0);
        if (r <= 0) return -1;
        received += (size_t)r;
    }
    return 0;
}

/* -------------------------------------------------------------------
 * handle_connection — processa uma conexão do proxy
 * ------------------------------------------------------------------- */
static void handle_connection(int client_fd)
{
    uint8_t  *payload_buf = NULL;
    int       ret = -1;

    /* --- lê flow_id (36 chars + '\n') --- */
    char flow_id[FLOW_ID_SIZE + 1];
    memset(flow_id, 0, sizeof(flow_id));

    /* lê byte a byte até encontrar '\n' ou atingir 37 chars */
    size_t fi = 0;
    while (fi < FLOW_ID_SIZE) {
        char c;
        ssize_t r = recv(client_fd, &c, 1, 0);
        if (r <= 0) goto done;
        if (c == '\n') break;
        flow_id[fi++] = c;
    }
    flow_id[fi] = '\0';

    /* --- lê payload_len (4 bytes big-endian) --- */
    uint8_t len_buf[4];
    if (recv_all(client_fd, len_buf, 4) < 0) goto done;
    uint32_t payload_len = ((uint32_t)len_buf[0] << 24)
                         | ((uint32_t)len_buf[1] << 16)
                         | ((uint32_t)len_buf[2] <<  8)
                         |  (uint32_t)len_buf[3];

    if (payload_len == 0 || payload_len > MAX_PAYLOAD_SIZE) {
        /* payload inválido — devolve Unknown */
        const char *resp = "Unknown\n";
        send(client_fd, resp, strlen(resp), 0);
        goto done;
    }

    /* --- lê src_ip, dst_ip, src_port, dst_port --- */
    uint32_t src_ip, dst_ip;
    uint16_t src_port_net, dst_port_net;

    if (recv_all(client_fd, &src_ip, 4) < 0)       goto done;
    if (recv_all(client_fd, &dst_ip, 4) < 0)        goto done;
    if (recv_all(client_fd, &src_port_net, 2) < 0)  goto done;
    if (recv_all(client_fd, &dst_port_net, 2) < 0)  goto done;

    uint16_t src_port = ntohs(src_port_net);
    uint16_t dst_port = ntohs(dst_port_net);

    /* --- lê payload --- */
    payload_buf = (uint8_t *)malloc(payload_len);
    if (!payload_buf) goto done;

    if (recv_all(client_fd, payload_buf, payload_len) < 0) goto done;

    /* --- classifica com nDPI (mutex protege o workflow) --- */
    char label[64];
    memset(label, 0, sizeof(label));

    pthread_mutex_lock(&g_workflow_mutex);
    const char *result = classify_payload(g_workflow,
                             flow_id,
                             src_ip, src_port,
                             dst_ip, dst_port,
                             payload_buf, (uint16_t)payload_len,
                             label, sizeof(label));
    pthread_mutex_unlock(&g_workflow_mutex);

    if (!result) {
        snprintf(label, sizeof(label), "Unknown");
    }

    /* --- envia resposta: "HTTP\n" --- */
    char resp[72];
    snprintf(resp, sizeof(resp), "%s\n", label);
    send(client_fd, resp, strlen(resp), 0);

    ret = 0;

done:
    if (ret != 0) {
        const char *err_resp = "Unknown\n";
        send(client_fd, err_resp, strlen(err_resp), MSG_NOSIGNAL);
    }
    free(payload_buf);
    close(client_fd);
}

/* -------------------------------------------------------------------
 * thread_func — cada conexão roda em thread separada
 * ------------------------------------------------------------------- */
typedef struct {
    int fd;
} thread_arg_t;

static void *thread_func(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;
    handle_connection(targ->fd);
    free(targ);
    return NULL;
}

/* -------------------------------------------------------------------
 * signal handler
 * ------------------------------------------------------------------- */
static void sig_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

/* -------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    const char *socket_path = SOCKET_PATH_DEFAULT;
    if (argc >= 2) socket_path = argv[1];

    signal(SIGTERM, sig_handler);
    signal(SIGINT,  sig_handler);
    signal(SIGPIPE, SIG_IGN);  /* ignora SIGPIPE — proxy pode fechar conexão */

    /* inicializa nDPI */
    g_workflow = init_workflow();
    if (!g_workflow) {
        fprintf(stderr, "[classifier] falha ao inicializar nDPI\n");
        return 1;
    }

    /* garante que o diretório do socket existe */
    char dir[256];
    strncpy(dir, socket_path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = '\0';
        if (mkdir(dir, 0755) < 0 && errno != EEXIST) {
            perror("[classifier] mkdir");
        }
    }

    /* remove socket antigo se existir */
    unlink(socket_path);

    /* cria Unix domain socket */
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[classifier] socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[classifier] bind");
        return 1;
    }

    /* permissão 0666 para que o proxy (outro container) consiga conectar */
    chmod(socket_path, 0666);

    if (listen(server_fd, BACKLOG) < 0) {
        perror("[classifier] listen");
        return 1;
    }

    fprintf(stderr, "[classifier] escutando em %s\n", socket_path);

    /* loop principal de accept */
    while (g_running) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;  /* sinal recebido */
            if (!g_running) break;
            perror("[classifier] accept");
            continue;
        }

        /* configura timeout de recebimento por conexão */
        struct timeval tv = { .tv_sec = RECV_TIMEOUT_SEC, .tv_usec = 0 };
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        /* despacha em thread separada */
        thread_arg_t *targ = (thread_arg_t *)malloc(sizeof(*targ));
        if (!targ) { close(client_fd); continue; }
        targ->fd = client_fd;

        pthread_t tid;
        if (pthread_create(&tid, NULL, thread_func, targ) != 0) {
            perror("[classifier] pthread_create");
            free(targ);
            close(client_fd);
            continue;
        }
        pthread_detach(tid);  /* thread limpa a si mesma ao terminar */
    }

    fprintf(stderr, "[classifier] encerrando...\n");
    close(server_fd);
    unlink(socket_path);
    free_workflow(&g_workflow);
    return 0;
}
