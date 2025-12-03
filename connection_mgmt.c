#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/param.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <inttypes.h>
#include <string.h>

#include "rdma_core.h"

/* InfiniBand configuration constants */
#define METADATA_SIZE (sizeof(struct rdma_metadata))
#define COMPLETION_QUEUE_SIZE 8
#define IB_PORT_NUM 1
#define TCP_BASE_PORT 8888
#define MAX_TRANSMISSION_UNIT (IBV_MTU_2048)
#define SERVICE_LEVEL 0
#define GID_TABLE_INDEX (-1)

static int system_page_size;

/*
 * Converts InfiniBand GID to wire format for network transmission
 * Transforms binary GID into hexadecimal string representation
 */
void convert_gid_to_wire(const union ibv_gid *gid_ptr, char wire_gid[]) {
    for (int segment = 0; segment < 4; ++segment)
        sprintf(&wire_gid[segment * 8], "%08x", htonl(*(uint32_t * )(gid_ptr->raw + segment * 4)));
}

/*
 * Converts wire format GID back to InfiniBand GID structure
 * Parses hexadecimal string into binary GID representation
 */
void convert_wire_to_gid(const char *wire_gid, union ibv_gid *gid_ptr) {
    char temp_buf[9];
    uint32_t segment_value;
    int segment;

    for (temp_buf[8] = 0, segment = 0; segment < 4; ++segment) {
        memcpy(temp_buf, wire_gid + segment * 8, 8);
        sscanf(temp_buf, "%x", &segment_value);
        *(uint32_t * )(&gid_ptr->raw[segment * 4]) = ntohl(segment_value);
    }
}

/*
 * Releases all resources associated with an IB connection
 * Properly destroys queue pairs, completion queues, and memory regions
 */
void destroy_ib_connection(struct ib_connection *conn) {
    if (conn == NULL)
        return;
    if (conn->queue_pair)
        ibv_destroy_qp(conn->queue_pair);
    if (conn->completion_q)
        ibv_destroy_cq(conn->completion_q);
    if (conn->buffer_mr)
        ibv_dereg_mr(conn->buffer_mr);
    if (conn->message_buf)
        free(conn->message_buf);
    free(conn);
}

/*
 * Comprehensive cleanup of process group resources
 * Deallocates all IB resources and connection structures
 */
int pg_close(void *group_handle) {
    struct process_group *pg = group_handle;

    if (pg == NULL)
        return EXIT_SUCCESS;

    if (pg->left_peer)
        destroy_ib_connection(pg->left_peer);
    if (pg->right_peer)
        destroy_ib_connection(pg->right_peer);

    for (int buf_idx = 0; buf_idx < DATA_BUFFER_COUNT; ++buf_idx) {
        if (pg->buffer_mrs[buf_idx])
            ibv_dereg_mr(pg->buffer_mrs[buf_idx]);
    }

    if (pg->protection_domain)
        ibv_dealloc_pd(pg->protection_domain);
    if (pg->ib_ctx)
        ibv_close_device(pg->ib_ctx);

    free(pg);
    return EXIT_SUCCESS;
}

/*
 * Posts receive work requests to prepare for incoming messages
 * Manages circular buffer indexing for efficient memory usage
 */
int post_receive_requests(struct ib_connection *conn, const int request_count) {
    struct ibv_sge scatter_gather = {
            .addr   = (uintptr_t) conn->message_buf,
            .length = conn->message_size,
            .lkey   = conn->buffer_mr->lkey
    };

    struct ibv_recv_wr receive_wr = {
            .wr_id   = 0,
            .sg_list = &scatter_gather,
            .num_sge = 1,
            .next    = NULL
    };
    struct ibv_recv_wr *failed_wr;

    int posted_count;
    for (posted_count = 0;
         posted_count < request_count && conn->pending_receives < conn->queue_depth / 2; ++posted_count) {
        const size_t buffer_address = (size_t)(conn->message_buf + conn->buffer_idx % (conn->queue_depth / 2));
        receive_wr.wr_id = ((uint64_t)(buffer_address - (size_t) conn->message_buf)) | ((uint64_t) WR_RECV << 32);
        scatter_gather.addr = (uintptr_t) buffer_address;
        if (ibv_post_recv(conn->queue_pair, &receive_wr, &failed_wr))
            break;
        conn->pending_receives++;
        conn->buffer_idx++;
        if (conn->buffer_idx >= (size_t) conn->queue_depth / 2) {
            conn->buffer_idx = 0;
        }
    }

    return posted_count;
}

/*
 * Initializes a single IB connection (left or right peer)
 * Sets up queue pairs, completion queues, and memory regions
 */
int setup_ib_connection(struct process_group *pg, const bool is_left_connection) {
    int result = EXIT_FAILURE;
    struct ib_connection *conn = calloc(1, sizeof(struct ib_connection));
    if (conn == NULL) {
        fprintf(stderr, "Memory allocation failed for IB connection\n");
        goto cleanup_and_exit;
    }

    conn->message_size = METADATA_SIZE;
    conn->queue_depth = COMPLETION_QUEUE_SIZE;
    conn->pending_receives = 0;
    conn->message_buf = calloc(1, conn->queue_depth * conn->message_size);
    if (conn->message_buf == NULL) {
        fprintf(stderr, "Failed to allocate message buffer\n");
        goto cleanup_and_exit;
    }
    conn->buffer_idx = 0;
    conn->buffer_mr = ibv_reg_mr(pg->protection_domain, conn->message_buf, conn->message_size * conn->queue_depth,
                                 IBV_ACCESS_LOCAL_WRITE);
    if (!conn->buffer_mr) {
        fprintf(stderr, "Memory region registration failed\n");
        goto cleanup_and_exit;
    }
    conn->completion_q = ibv_create_cq(pg->ib_ctx, COMPLETION_QUEUE_SIZE, NULL, NULL, 0);
    if (!conn->completion_q) {
        fprintf(stderr, "Completion queue creation failed\n");
        goto cleanup_and_exit;
    }

    {
        struct ibv_qp_init_attr qp_attributes = {
                .send_cq = conn->completion_q,
                .recv_cq = conn->completion_q,
                .cap     = {
                        .max_send_wr  = COMPLETION_QUEUE_SIZE / 2,
                        .max_recv_wr  = COMPLETION_QUEUE_SIZE / 2,
                        .max_send_sge = 1,
                        .max_recv_sge = 1
                },
                .qp_type = IBV_QPT_RC
        };
        conn->queue_pair = ibv_create_qp(pg->protection_domain, &qp_attributes);
        if (!conn->queue_pair) {
            fprintf(stderr, "Queue pair creation failed\n");
            goto cleanup_and_exit;
        }
    }

    {
        struct ibv_qp_attr qp_attr = {
                .qp_state        = IBV_QPS_INIT,
                .pkey_index      = 0,
                .port_num        = IB_PORT_NUM,
                .qp_access_flags = IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE
        };
        if (ibv_modify_qp(conn->queue_pair, &qp_attr,
                          IBV_QP_STATE |
                          IBV_QP_PKEY_INDEX |
                          IBV_QP_PORT |
                          IBV_QP_ACCESS_FLAGS)) {
            fprintf(stderr, "Queue pair INIT state transition failed\n");
            goto cleanup_and_exit;
        }
    }

    conn->pending_receives = post_receive_requests(conn, conn->queue_depth / 2);
    if (conn->pending_receives < conn->queue_depth / 2) {
        fprintf(stderr, "Failed to post receive requests: %d\n", conn->pending_receives);
        goto cleanup_and_exit;
    }

    if (ibv_query_port(pg->ib_ctx, IB_PORT_NUM, &conn->port_info)) {
        fprintf(stderr, "Port information query failed\n");
        goto cleanup_and_exit;
    }

    if (is_left_connection) {
        pg->left_peer = conn;
    } else {
        pg->right_peer = conn;
    }
    result = EXIT_SUCCESS;

    cleanup_and_exit:
    if (result != EXIT_SUCCESS) {
        destroy_ib_connection(conn);
    }

    return result;
}

/*
 * Allocates and initializes all IB resources for the process group
 * Creates protection domain and sets up left/right connections
 */
int allocate_ib_resources(struct process_group **group_handle) {
    int result = EXIT_FAILURE;
    struct ibv_device **device_list = NULL;

    system_page_size = sysconf(_SC_PAGESIZE);

    struct process_group *pg = calloc(1, sizeof(struct process_group));
    if (!pg) {
        fprintf(stderr, "Process group allocation failed\n");
        goto cleanup_resources;
    }

    device_list = ibv_get_device_list(NULL);
    if (!device_list) {
        fprintf(stderr, "Failed to enumerate IB devices");
        goto cleanup_resources;
    }

    struct ibv_device *ib_device = *device_list;
    if (!ib_device) {
        fprintf(stderr, "No InfiniBand devices detected\n");
        return 1;
    }

    pg->ib_ctx = ibv_open_device(ib_device);
    if (!pg->ib_ctx) {
        fprintf(stderr, "Device context creation failed for %s\n", ibv_get_device_name(ib_device));
        goto cleanup_resources;
    }

    pg->protection_domain = ibv_alloc_pd(pg->ib_ctx);
    if (!pg->protection_domain) {
        fprintf(stderr, "Protection domain allocation failed\n");
        goto cleanup_resources;
    }

    if (setup_ib_connection(pg, true) != EXIT_SUCCESS ||
        setup_ib_connection(pg, false) != EXIT_SUCCESS) {
        fprintf(stderr, "IB connection setup failed\n");
        goto cleanup_resources;
    }

    *group_handle = pg;
    result = EXIT_SUCCESS;

    cleanup_resources:
    if (device_list != NULL) {
        ibv_free_device_list(device_list);
    }

    if (result != EXIT_SUCCESS && pg != NULL) {
        pg_close(pg);
    }

    return result;
}