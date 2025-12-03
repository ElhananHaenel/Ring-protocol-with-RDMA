#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <string.h>

#include <time.h>

#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/socket.h>

#include <netdb.h>
#include "rdma_core.h"
#include <sys/types.h>

struct exchange_resources {
    struct addrinfo *addr_info;
    int socket;
    char *message_buffer;
    char *gid_string;
};

/* Helper functions for resource management */
static struct exchange_resources *create_exchange_resources() {
    struct exchange_resources *res = calloc(1, sizeof(struct exchange_resources));
    if (!res) return NULL;

    res->addr_info = NULL;
    res->socket = -1;
    res->message_buffer = malloc(sizeof("0000:000000:000000:00000000000000000000000000000000"));
    res->gid_string = malloc(33);

    if (!res->message_buffer || !res->gid_string) {
        free(res->message_buffer);
        free(res->gid_string);
        free(res);
        return NULL;
    }

    return res;
}

static void cleanup_exchange_resources(struct exchange_resources *res) {
    if (!res) return;

    if (res->addr_info)
        freeaddrinfo(res->addr_info);
    if (res->socket >= 0)
        close(res->socket);
    free(res->message_buffer);
    free(res->gid_string);
    free(res);
}

/* Network configuration for peer discovery */

#define TCP_BASE_PORT 12345
#define IB_PORT_NUM 1
#define MAX_TRANSMISSION_UNIT (IBV_MTU_2048)
#define SERVICE_LEVEL 0
#define GID_TABLE_INDEX (-1)

/* External functions from connection_mgmt.c */
extern void convert_gid_to_wire(const union ibv_gid *gid_ptr, char wire_gid[]);

extern void convert_wire_to_gid(const char *wire_gid, union ibv_gid *gid_ptr);

/*
 * Establishes connection between two queue pairs using exchanged parameters
 * Transitions QP through RTR (Ready to Receive) and RTS (Ready to Send) states
 */
int establish_qp_connection(const struct ib_connection *conn, const int local_psn,
                            const struct ib_conn_params *remote_params) {
    struct qp_config {
        uint8_t timeout;
        uint8_t retry_count;
        uint8_t rnr_retry;
    } config = {12, 6, 6};  // Different values

    struct ibv_qp_attr qp_attr = {
            .qp_state        = IBV_QPS_RTR,
            .path_mtu        = MAX_TRANSMISSION_UNIT,
            .dest_qp_num    = remote_params->qp_number,
            .rq_psn            = remote_params->packet_seq_num,
            .max_dest_rd_atomic    = 1,
            .min_rnr_timer        = 12,
            .ah_attr        = {
                    .is_global    = 0,
                    .dlid            = remote_params->local_id,
                    .sl                 = SERVICE_LEVEL,
                    .src_path_bits     = 0,
                    .port_num         = IB_PORT_NUM,
            }
    };

    if (remote_params->global_id.global.interface_id) {
        qp_attr.ah_attr.is_global = 1;
        qp_attr.ah_attr.grh.hop_limit = 1;
        qp_attr.ah_attr.grh.dgid = remote_params->global_id;
        qp_attr.ah_attr.grh.sgid_index = GID_TABLE_INDEX;
    }
    if (ibv_modify_qp(conn->queue_pair, &qp_attr,
                      IBV_QP_STATE |
                      IBV_QP_AV |
                      IBV_QP_PATH_MTU |
                      IBV_QP_DEST_QPN |
                      IBV_QP_RQ_PSN |
                      IBV_QP_MAX_DEST_RD_ATOMIC |
                      IBV_QP_MIN_RNR_TIMER)) {
        fprintf(stderr, "QP RTR state transition failed\n");
        return EXIT_FAILURE;
    }

    qp_attr.qp_state = IBV_QPS_RTS;
    qp_attr.timeout = config.timeout;
    qp_attr.retry_cnt = config.retry_count;
    qp_attr.rnr_retry = config.rnr_retry;
    qp_attr.sq_psn = local_psn;
    qp_attr.max_rd_atomic = 1;
    if (ibv_modify_qp(conn->queue_pair, &qp_attr,
                      IBV_QP_STATE |
                      IBV_QP_TIMEOUT |
                      IBV_QP_RETRY_CNT |
                      IBV_QP_RNR_RETRY |
                      IBV_QP_SQ_PSN |
                      IBV_QP_MAX_QP_RD_ATOMIC)) {
        fprintf(stderr, "QP RTS state transition failed\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/*
 * Client-side connection parameter exchange via TCP
 * Connects to remote server and exchanges IB connection parameters
 */
struct ib_conn_params *exchange_as_client(const char *server_hostname,
                                          const struct ib_conn_params *local_params, const int node_rank,
                                          const int total_nodes) {

    const struct addrinfo addr_hints = {
            .ai_family   = AF_INET,     // IPv4
            .ai_socktype = SOCK_STREAM, // TCP
            .ai_flags    = 0            // No special flags needed for client
    };

    struct exchange_resources *res = create_exchange_resources();
    if (!res) return NULL;

    struct ib_conn_params *remote_params = NULL;
    char message_buffer[sizeof "0000:000000:000000:00000000000000000000000000000000"];
    char gid_string[33];

    char port_string[16] = {0};
    const int tcp_port = TCP_BASE_PORT + (node_rank + 1) % total_nodes;
    snprintf(port_string, 16, "%d", tcp_port);

    const int addr_result = getaddrinfo(server_hostname, port_string, &addr_hints, &res->addr_info);
    if (addr_result != 0) {
        fprintf(stderr, "%s for %s:%d\n", gai_strerror(addr_result), server_hostname, tcp_port);
        goto cleanup_and_return;
    }

    res->socket = socket(res->addr_info->ai_family, res->addr_info->ai_socktype, res->addr_info->ai_protocol);
    const int socket_option = 1;
    if (setsockopt(res->socket, SOL_SOCKET, SO_REUSEADDR, &socket_option, sizeof(socket_option)) < 0) {
        close(res->socket);
        res->socket = -1;
    }

    if (res->socket >= 0) {
        struct timespec retry_delay;
        retry_delay.tv_sec = 1;
        retry_delay.tv_nsec = 0;
        while (connect(res->socket, res->addr_info->ai_addr, res->addr_info->ai_addrlen)) {
            nanosleep(&retry_delay, NULL);
        }
    }

    if (res->socket < 0) {
        fprintf(stderr, "Connection failed to %s:%d\n", server_hostname, tcp_port);
        goto cleanup_and_return;
    }

    convert_gid_to_wire(&local_params->global_id, gid_string);
    sprintf(message_buffer, "%04x:%06x:%06x:%s", local_params->local_id, local_params->qp_number,
            local_params->packet_seq_num, gid_string);
    if (write(res->socket, message_buffer, sizeof message_buffer) != sizeof message_buffer) {
        fprintf(stderr, "Failed to send local connection parameters\n");
        goto cleanup_and_return;
    }

    if (read(res->socket, message_buffer, sizeof message_buffer) != sizeof message_buffer) {
        perror("client read operation");
        fprintf(stderr, "Failed to receive remote connection parameters\n");
        goto cleanup_and_return;
    }

    write(res->socket, "done", sizeof "done");

    remote_params = malloc(sizeof *remote_params);
    if (!remote_params)
        goto cleanup_and_return;

    sscanf(message_buffer, "%x:%x:%x:%s", &remote_params->local_id, &remote_params->qp_number,
           &remote_params->packet_seq_num, gid_string);
    convert_wire_to_gid(gid_string, &remote_params->global_id);

    cleanup_and_return:
    cleanup_exchange_resources(res);
    return remote_params;
}

/*
 * Server-side connection parameter exchange via TCP
 * Listens for incoming connection and exchanges IB parameters
 */
static struct ib_conn_params *
exchange_as_server(const struct ib_connection *conn, const struct ib_conn_params *local_params, const int node_rank) {
    struct addrinfo *addr_info = NULL;
    const struct addrinfo addr_hints = {
            .ai_flags    = AI_PASSIVE,
            .ai_family   = AF_INET,
            .ai_socktype = SOCK_STREAM
    };
    char port_string[16];
    char message_buffer[sizeof "0000:000000:000000:00000000000000000000000000000000"];
    int listen_socket = -1, client_socket = -1;
    struct ib_conn_params *remote_params = NULL;
    char gid_string[33];

    const int tcp_port = TCP_BASE_PORT + node_rank;
    snprintf(port_string, 16, "%d", tcp_port);

    int addr_result = getaddrinfo(NULL, port_string, &addr_hints, &addr_info);
    if (addr_result != 0) {
        fprintf(stderr, "%s for port %d\n", gai_strerror(addr_result), tcp_port);
        goto cleanup_and_return;
    }

    for (const struct addrinfo *addr_ptr = addr_info; addr_ptr; addr_ptr = addr_ptr->ai_next) {
        listen_socket = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
        if (listen_socket >= 0) {
            addr_result = 1;
            setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &addr_result, sizeof addr_result);
            if (!bind(listen_socket, addr_ptr->ai_addr, addr_ptr->ai_addrlen))
                break;
            close(listen_socket);
            listen_socket = -1;
        }
    }

    if (listen_socket < 0) {
        fprintf(stderr, "Failed to bind to port %d\n", tcp_port);
        goto cleanup_and_return;
    }

    listen(listen_socket, 1);
    client_socket = accept(listen_socket, NULL, 0);
    close(listen_socket);
    if (client_socket < 0) {
        fprintf(stderr, "TCP accept operation failed\n");
        goto cleanup_and_return;
    }

    addr_result = read(client_socket, message_buffer, sizeof message_buffer);
    if (addr_result != sizeof message_buffer) {
        perror("server read operation");
        fprintf(stderr, "%d/%d: Failed to read remote parameters\n", addr_result, (int) sizeof message_buffer);
        goto cleanup_and_return;
    }

    remote_params = malloc(sizeof *remote_params);
    if (!remote_params)
        goto cleanup_and_return;

    sscanf(message_buffer, "%x:%x:%x:%s", &remote_params->local_id, &remote_params->qp_number,
           &remote_params->packet_seq_num, gid_string);
    convert_wire_to_gid(gid_string, &remote_params->global_id);

    if (establish_qp_connection(conn, local_params->packet_seq_num, remote_params) != EXIT_SUCCESS) {
        fprintf(stderr, "Queue pair connection establishment failed\n");
        free(remote_params);
        remote_params = NULL;
        goto cleanup_and_return;
    }

    convert_gid_to_wire(&local_params->global_id, gid_string);
    sprintf(message_buffer, "%04x:%06x:%06x:%s", local_params->local_id, local_params->qp_number,
            local_params->packet_seq_num, gid_string);
    if (write(client_socket, message_buffer, sizeof message_buffer) != sizeof message_buffer) {
        fprintf(stderr, "Failed to send local parameters\n");
        free(remote_params);
        remote_params = NULL;
        goto cleanup_and_return;
    }

    read(client_socket, message_buffer, sizeof message_buffer);

    cleanup_and_return:
    if (addr_info != NULL)
        freeaddrinfo(addr_info);
    if (listen_socket >= 0)
        close(listen_socket);
    if (client_socket >= 0)
        close(client_socket);
    return remote_params;
}

/*
 * Initializes connection parameters for a given IB connection
 * Sets up local identifiers and generates random packet sequence number
 */
int setup_connection_parameters(const struct ib_connection *conn, struct ib_conn_params *conn_params) {
    conn_params->local_id = conn->port_info.lid;
    if (conn->port_info.link_layer == IBV_LINK_LAYER_INFINIBAND && !conn_params->local_id) {
        fprintf(stderr, "Failed to obtain local LID\n");
        return EXIT_FAILURE;
    }
    memset(&conn_params->global_id, 0, sizeof(conn_params->global_id));
    conn_params->qp_number = conn->queue_pair->qp_num;
    conn_params->packet_seq_num = lrand48() & 0xffffff;
    inet_ntop(AF_INET6, &conn_params->global_id, (char *) conn_params->global_id.raw,
              sizeof(conn_params->global_id.raw));

    return EXIT_SUCCESS;
}

/*
 * Initializes connection parameters for a given IB connection
 * Sets up local identifiers and generates random packet sequence number
 */
int connect_process_group(const int node_rank, void **group_handle, const char **node_list, const int node_count) {
    if (group_handle == NULL || node_list == NULL || node_count <= 0) {
        fprintf(stderr, "Invalid arguments to connect_process_group\n");
        return EXIT_FAILURE;
    }

    struct process_group *pg = NULL;
    struct ib_conn_params left_connection = {0};
    struct ib_conn_params right_connection = {0};
    struct ib_conn_params *left_remote_params = NULL;
    struct ib_conn_params *right_remote_params = NULL;

    // Allocate resources
    if (allocate_ib_resources((struct process_group **) group_handle) != EXIT_SUCCESS) {
        fprintf(stderr, "IB resource allocation failed for process group\n");
        return EXIT_FAILURE;
    }
    pg = *(struct process_group **) group_handle;
    pg->total_nodes = node_count;
    pg->node_rank = node_rank;

    // Setup connection parameters
    if (setup_connection_parameters(pg->left_peer, &left_connection) != EXIT_SUCCESS ||
        setup_connection_parameters(pg->right_peer, &right_connection) != EXIT_SUCCESS) {
        fprintf(stderr, "Connection parameter initialization failed\n");
        pg_close(pg);
        *group_handle = NULL;
        return EXIT_FAILURE;
    }

    // Handle client/server roles
    const char *right_node = node_list[(node_rank + 1) % node_count];

    if (node_rank % 2 == 0) {
        printf("Connecting to right node: %s\n", right_node);

        right_remote_params = exchange_as_client(right_node, &right_connection, node_rank, node_count);
        if (!right_remote_params ||
            establish_qp_connection(pg->right_peer, right_connection.packet_seq_num, right_remote_params) !=
            EXIT_SUCCESS) {
            fprintf(stderr, "Right-side connection failed\n");
            pg_close(pg);
            free(right_remote_params);
            *group_handle = NULL;
            return EXIT_FAILURE;
        }

        left_remote_params = exchange_as_server(pg->left_peer, &left_connection, node_rank);
        if (!left_remote_params) {
            fprintf(stderr, "Server exchange with left node failed\n");
            pg_close(pg);
            free(right_remote_params);
            *group_handle = NULL;
            return EXIT_FAILURE;
        }
    } else {
        left_remote_params = exchange_as_server(pg->left_peer, &left_connection, node_rank);
        if (!left_remote_params) {
            fprintf(stderr, "Server exchange with left node failed\n");
            pg_close(pg);
            *group_handle = NULL;
            return EXIT_FAILURE;
        }

        printf("Connecting to right node: %s\n", right_node);
        right_remote_params = exchange_as_client(right_node, &right_connection, node_rank, node_count);
        if (!right_remote_params ||
            establish_qp_connection(pg->right_peer, right_connection.packet_seq_num, right_remote_params) !=
            EXIT_SUCCESS) {
            fprintf(stderr, "Client connection to right node failed\n");
            pg_close(pg);
            free(left_remote_params);
            *group_handle = NULL;
            return EXIT_FAILURE;
        }
    }

    // Initialize buffers
    for (int buf_idx = 0; buf_idx < DATA_BUFFER_COUNT; ++buf_idx) {
        pg->buffer_mrs[buf_idx] = NULL;
    }

    // Free temporary allocations
    free(right_remote_params);
    free(left_remote_params);

    return EXIT_SUCCESS;
}
