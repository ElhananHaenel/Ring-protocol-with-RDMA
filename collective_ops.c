#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "rdma_core.h"

/* External functions from rdma_operations.c */
extern int
execute_ring_pipeline(const struct process_group *pg, const size_t chunk_size, void *source_buffer, void *target_buffer,
                      const size_t element_size, const bool perform_reduction,
                      const data_type_t data_type, const reduce_op_t reduction_op);

/*
 * Performs reduce-scatter collective operation across the process group
 * Distributes and reduces data chunks in a ring pattern
 */
int execute_reduce_scatter(void *source_buffer, void *result_buffer, const int element_size, const size_t chunk_size,
                           void *group_handle, const data_type_t data_type, const reduce_op_t reduction_op) {
    int operation_status = EXIT_FAILURE;
    struct process_group *pg = group_handle;

    if (execute_ring_pipeline(pg, chunk_size, source_buffer, result_buffer, element_size, true, data_type,
                              reduction_op) != EXIT_SUCCESS) {
        fprintf(stderr, "Ring pipeline execution failed\n");
    }

    operation_status = EXIT_SUCCESS;

    return operation_status;
}

/*
 * Performs all-gather collective operation across the process group
 * Collects data from all nodes and distributes complete result
 */
int execute_all_gather(void *source_buffer, void *result_buffer, void *group_handle, const int element_size,
                       const size_t chunk_size, const data_type_t data_type) {
    int operation_status = EXIT_FAILURE;
    struct process_group *pg = group_handle;

    if (execute_ring_pipeline(pg, chunk_size, source_buffer, result_buffer, element_size, false, data_type, 0) !=
        EXIT_SUCCESS) {
        fprintf(stderr, "Ring pipeline execution failed\n");
    }

    operation_status = EXIT_SUCCESS;

    return operation_status;
}

/*
 * Performs all-reduce collective operation by combining reduce-scatter and all-gather
 * Reduces all data and distributes the complete result to all nodes
 */
int pg_all_reduce(void *source_buffer, void *result_buffer, void *group_handle, const int element_count,
                  const data_type_t data_type, const reduce_op_t reduction_op) {
    const struct process_group *pg = group_handle;
    const size_t element_size = (data_type == DATA_INT) ? sizeof(int) :
                                (data_type == DATA_DOUBLE) ? sizeof(double) : 0;
    const size_t chunk_size = element_count * element_size / pg->total_nodes;


    if (execute_reduce_scatter(source_buffer, result_buffer, element_size, chunk_size, group_handle, data_type,
                               reduction_op) != EXIT_SUCCESS) {
        fprintf(stderr, "Reduce-scatter phase failed\n");
        return EXIT_FAILURE;
    }
    // All-gather the reduced results
    if (execute_all_gather(result_buffer, result_buffer, group_handle, element_size, chunk_size, data_type) !=
        EXIT_SUCCESS) {
        fprintf(stderr, "All-gather phase failed\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}