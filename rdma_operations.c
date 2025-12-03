#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include "rdma_core.h"

/* Maximum chunk size for RDMA read operations */
#define RDMA_READ_LIMIT (1 << 20)

/* External function from connection_mgmt.c */
extern int post_receive_requests(struct ib_connection *conn, const int request_count);

/*
 * Waits for completion of a specific work request type
 * Polls completion queue until matching completion arrives
 */
int await_work_completion(struct ib_connection *conn, work_request_id_t expected_wr_id,
                          struct rdma_metadata **metadata_out) {
    struct ibv_wc wc;
    int poll_result;

    // Continuously poll the completion queue until a work completion is found
    while (1) {
        poll_result = ibv_poll_cq(conn->completion_q, 1, &wc);
        if (poll_result < 0) {
            fprintf(stderr, "Error polling completion queue: %d\n", poll_result);
            return EXIT_FAILURE;
        }
        if (poll_result == 0) {
            continue; // No completion yet, keep polling
        }
        break; // Got a completion
    }

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Work completion error: %s (%d), wr_id: %d\n",
                ibv_wc_status_str(wc.status), wc.status, (int) wc.wr_id);
        return EXIT_FAILURE;
    }

    int wr_type = (int) (wc.wr_id >> 32);

    if (wr_type == WR_RECV && expected_wr_id == WR_RECV) {
        conn->pending_receives--;
        size_t offset = wc.wr_id & 0xFFFFFFFF;
        if (post_receive_requests(conn, 1) != 1) {
            return EXIT_FAILURE;
        }
        if (metadata_out) {
            *metadata_out = (struct rdma_metadata *) ((char *) conn->message_buf + offset);
        }
        return EXIT_SUCCESS;
    }

    if ((wr_type == WR_READ && expected_wr_id == WR_READ) ||
        (wr_type == WR_SEND && expected_wr_id == WR_SEND)) {
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}

/*
 * Sends RDMA metadata to enable remote memory access
 * Transmits buffer address, size, and remote key information
 */
int transmit_rdma_metadata(const struct ib_connection *conn, const struct ibv_mr *memory_region,
                           const uintptr_t buffer_address, const size_t data_size) {
    conn->message_buf[conn->queue_depth / 2].buffer_addr = buffer_address;
    conn->message_buf[conn->queue_depth / 2].data_size = data_size;
    conn->message_buf[conn->queue_depth / 2].remote_key = memory_region->rkey;

    struct ibv_sge scatter_gather = {
            .addr = (uintptr_t) & conn->message_buf[conn->queue_depth / 2],
            .length = conn->message_size,
            .lkey = conn->buffer_mr->lkey
    };

    struct ibv_send_wr send_request = {
            .wr_id   = (uint64_t) WR_SEND << 32,
            .sg_list = &scatter_gather,
            .num_sge = 1,
            .opcode  = IBV_WR_SEND,
            .send_flags = IBV_SEND_SIGNALED,
            .next    = NULL
    };

    struct ibv_send_wr *failed_wr = NULL;
    const int send_result = ibv_post_send(conn->queue_pair, &send_request, &failed_wr);

    if (send_result) {
        fprintf(stderr, "Send request posting failed: %s\n", strerror(send_result));
        if (failed_wr) {
            fprintf(stderr, "Failed work request ID: %lu\n", failed_wr->wr_id);
        }
        return EXIT_FAILURE;
    }

    if (await_work_completion((struct ib_connection *) conn, WR_SEND, NULL) != EXIT_SUCCESS) {
        fprintf(stderr, "RDMA metadata send completion failed\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/*
 * Performs RDMA read operation from remote memory
 * Reads data from remote buffer into local memory region
 */
int execute_rdma_read(const struct ib_connection *conn, const struct rdma_metadata *remote_info,
                      const struct ibv_mr *local_mr, const size_t read_offset) {
    if (local_mr->length < (size_t) remote_info->data_size) {
        return EXIT_FAILURE;
    }

    struct ibv_sge scatter_gather = {
            .addr   = (uintptr_t)((char *) local_mr->addr + read_offset),
            .length = remote_info->data_size,
            .lkey   = local_mr->lkey
    };

    struct ibv_send_wr read_request = {
            .wr_id      = (uint64_t) WR_READ << 32,
            .sg_list    = &scatter_gather,
            .num_sge    = 1,
            .opcode     = IBV_WR_RDMA_READ,
            .send_flags = IBV_SEND_SIGNALED,
            .wr.rdma.remote_addr = (uintptr_t)((char *) remote_info->buffer_addr + read_offset),
            .wr.rdma.rkey        = remote_info->remote_key
    };

    struct ibv_send_wr *failed_wr = NULL;
    const int read_result = ibv_post_send(conn->queue_pair, &read_request, &failed_wr);
    if (read_result) {
        fprintf(stderr, "RDMA read request posting failed: %d\n", read_result);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/*
 * Sends completion notification after RDMA read finishes
 * Notifies remote peer that read operation is complete
 */
int signal_read_completion(struct ib_connection *conn) {
    conn->message_buf[conn->queue_depth / 2].buffer_addr = (uintptr_t) 0;
    conn->message_buf[conn->queue_depth / 2].data_size = 0;
    conn->message_buf[conn->queue_depth / 2].remote_key = 0;

    struct ibv_sge scatter_gather = {
            .addr = (uintptr_t) & conn->message_buf[conn->queue_depth / 2],
            .length = conn->message_size,
            .lkey = conn->buffer_mr->lkey
    };

    struct ibv_send_wr send_request = {
            .wr_id   = (uint64_t) WR_SEND << 32,
            .sg_list = &scatter_gather,
            .num_sge = 1,
            .opcode  = IBV_WR_SEND,
            .send_flags = IBV_SEND_SIGNALED,
            .next    = NULL
    };

    struct ibv_send_wr *failed_wr = NULL;
    const int send_result = ibv_post_send(conn->queue_pair, &send_request, &failed_wr);

    if (send_result) {
        fprintf(stderr, "Completion signal send failed: %s\n", strerror(send_result));
        if (failed_wr) {
            fprintf(stderr, "Failed work request ID: %lu\n", failed_wr->wr_id);
        }
        return EXIT_FAILURE;
    }

    return await_work_completion(conn, WR_SEND, NULL);
}

/*
 * Applies reduction operation to two data arrays
 * Combines source data into destination using specified operation
 */
int apply_reduction_operation(const void *source_data, void *target_data, const int element_count,
                              const data_type_t data_type, const reduce_op_t reduction_op) {
    if (data_type >= DATA_TYPE_MAX || reduction_op >= REDUCE_OP_MAX)
        return EXIT_FAILURE;

    const reduction_func_t operation_func = reduction_table[data_type][reduction_op];
    if (!operation_func)
        return EXIT_FAILURE;

    operation_func(target_data, source_data, element_count);
    return EXIT_SUCCESS;
}


int perform_rdma_read_sequence(const struct process_group *pg, struct rdma_metadata *remote_metadata, size_t chunk_size,
                               void *source_buffer, void *target_buffer, size_t element_size, int current_read_idx,
                               bool perform_reduction, int read_buf_index, data_type_t data_type,
                               reduce_op_t reduction_op) {
    size_t remaining = remote_metadata->data_size;
    size_t offset = 0;

    while (remaining > 0) {
        size_t read_size = remaining > RDMA_READ_LIMIT ? RDMA_READ_LIMIT : remaining;
        struct rdma_metadata read_metadata = {
                .buffer_addr = remote_metadata->buffer_addr + offset,
                .data_size = read_size,
                .remote_key = remote_metadata->remote_key
        };

        int result = execute_rdma_read(pg->left_peer, &read_metadata, pg->buffer_mrs[read_buf_index],
                                       offset);
        if (result != EXIT_SUCCESS)
            return EXIT_FAILURE;

        // Wait for completion of this read
        if (await_work_completion(pg->left_peer, WR_READ, NULL) != EXIT_SUCCESS) {
            return EXIT_FAILURE;
        }

        if (perform_reduction) {
            void *dest_ptr = (char *) target_buffer + current_read_idx * chunk_size + offset;
            void *src_ptr = (char *) source_buffer + current_read_idx * chunk_size + offset;

            if (apply_reduction_operation(src_ptr, dest_ptr, read_size / element_size, data_type, reduction_op) !=
                EXIT_SUCCESS)
                return EXIT_FAILURE;

        }
        remaining -= read_size;
        offset += read_size;
    }

    return EXIT_SUCCESS;
}


int execute_ring_pipeline(struct process_group *pg, size_t chunk_size, void *source_buffer, void *target_buffer,
                          size_t element_size, bool perform_reduction, data_type_t data_type,
                          reduce_op_t reduction_op) {
    int buf_index = 0;
    int index_to_read = 0;

    /* Register initial buffer (buf_index) depending on reduction mode */
    void *initial_region = NULL;
    if (!perform_reduction) {
        initial_region = (void *) ((uintptr_t) target_buffer + pg->node_rank * chunk_size);
    } else {
        initial_region = (void *) ((uintptr_t) source_buffer +
                                   ((pg->node_rank + pg->total_nodes - 1) % pg->total_nodes) * chunk_size);
    }

    if (pg->buffer_mrs[buf_index] != NULL) {
        ibv_dereg_mr(pg->buffer_mrs[buf_index]);
        pg->buffer_mrs[buf_index] = NULL;
    }
    pg->buffer_mrs[buf_index] = ibv_reg_mr(pg->protection_domain,
                                           initial_region, chunk_size,
                                           IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
    if (!pg->buffer_mrs[buf_index]) {
        fprintf(stderr, "Memory region registration failed for buffer %d\n", buf_index);
        return EXIT_FAILURE;
    }

    for (int iteration = 0; iteration < pg->total_nodes - 1; iteration++) {
        /* Compute the address that will be advertised to the right peer */
        index_to_read = (pg->node_rank - 1 - iteration + pg->total_nodes) % pg->total_nodes;

        uintptr_t reading_buffer_address;
        if (!perform_reduction) {
            reading_buffer_address = (uintptr_t) target_buffer +
                                     ((pg->node_rank - iteration + pg->total_nodes) % pg->total_nodes) * chunk_size;
        } else if (iteration == 0) {
            reading_buffer_address = (uintptr_t) source_buffer +
                                     ((pg->node_rank - 1 + pg->total_nodes) % pg->total_nodes) * chunk_size;
        } else {
            reading_buffer_address = (uintptr_t) target_buffer +
                                     ((pg->node_rank - 1 - iteration + pg->total_nodes) % pg->total_nodes) * chunk_size;
        }

        /* Prepare and register the alternate buffer for incoming RDMA reads */
        void *writing_target_region;
        if (!perform_reduction) {
            writing_target_region = (void *) ((uintptr_t) target_buffer +
                                              ((pg->node_rank - 1 - iteration + pg->total_nodes) % pg->total_nodes) *
                                              chunk_size);
        } else {
            writing_target_region = (void *) ((uintptr_t) target_buffer +
                                              ((pg->node_rank - 2 - iteration + pg->total_nodes) % pg->total_nodes) *
                                              chunk_size);
        }

        int alt_index = buf_index ^ 1;
        if (pg->buffer_mrs[alt_index] != NULL) {
            ibv_dereg_mr(pg->buffer_mrs[alt_index]);
            pg->buffer_mrs[alt_index] = NULL;
        }
        pg->buffer_mrs[alt_index] = ibv_reg_mr(pg->protection_domain,
                                               writing_target_region, chunk_size,
                                               IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
        if (!pg->buffer_mrs[alt_index]) {
            fprintf(stderr, "Memory region registration failed for buffer %d\n", alt_index);
            ibv_dereg_mr(pg->buffer_mrs[buf_index]);
            pg->buffer_mrs[buf_index] = NULL;
            return EXIT_FAILURE;
        }

        /* Send metadata to right peer */
        if (transmit_rdma_metadata(pg->right_peer, pg->buffer_mrs[buf_index], reading_buffer_address, chunk_size) !=
            EXIT_SUCCESS)
            return EXIT_FAILURE;

        /* Receive metadata from left peer */
        struct rdma_metadata *remote_metadata = NULL;
        if (await_work_completion(pg->left_peer, WR_RECV, &remote_metadata) != EXIT_SUCCESS || !remote_metadata)
            return EXIT_FAILURE;

        /* Perform RDMA reads (possibly multiple chunks) and optionally reduce */
        if (perform_rdma_read_sequence(pg, remote_metadata, chunk_size, source_buffer, target_buffer,
                                       element_size, index_to_read, perform_reduction,
                                       alt_index, data_type, reduction_op) != EXIT_SUCCESS)
            return EXIT_FAILURE;

        /* Notify left peer reading is complete */
        if (signal_read_completion(pg->left_peer) != EXIT_SUCCESS)
            return EXIT_FAILURE;

        /* Await ack from right peer */
        if (await_work_completion(pg->right_peer, WR_RECV, NULL) != EXIT_SUCCESS)
            return EXIT_FAILURE;

        /* Update read index and flip buffer index */
        buf_index = alt_index;
    }

    return EXIT_SUCCESS;
}