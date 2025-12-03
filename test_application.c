#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include "rdma_core.h"


#define NUM_SIZES 13
#define NUM_ITER 10

int main(int argc, char const *argv[]) {
    int current_rank = -1;
    const char *node_hostnames[32];
    int total_nodes = 0;

    if (argc < 5) {
        fprintf(stderr, "Usage: %s -myindex <rank> -list <node1> <node2> ...\n", argv[0]);
        return 1;
    }

    for (int arg_idx = 1; arg_idx < argc; ++arg_idx) {
        if (strcmp(argv[arg_idx], "-myindex") == 0 && arg_idx + 1 < argc) {
            current_rank = atoi(argv[++arg_idx]);
        } else if (strcmp(argv[arg_idx], "-list") == 0) {
            for (int host_idx = arg_idx + 1; host_idx < argc && total_nodes < 32; ++host_idx) {
                node_hostnames[total_nodes++] = argv[host_idx];
            }
            break;
        }
    }

    if (current_rank < 0 || total_nodes == 0) {
        fprintf(stderr, "Missing required arguments: rank or node list\n");
        return 1;
    }

    char local_hostname[256];
    if (gethostname(local_hostname, sizeof(local_hostname)) != 0) {
        perror("hostname retrieval failed");
        return 1;
    }

    size_t buffer_sizes[NUM_SIZES] = {
            4096, 8192, 16384, 32768, 65536,
            131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216
    };

    for (int i = 0; i < NUM_SIZES; ++i) {

        void *process_group_handle = NULL;
        if (connect_process_group(current_rank, &process_group_handle, node_hostnames, total_nodes) != 0) {
            fprintf(stderr, "Process group initialization failed\n");
            return EXIT_FAILURE;
        }


        size_t buf_size = buffer_sizes[i];
        size_t element_count = (buf_size >> 2) / sizeof(int);

        int *test_data = malloc(element_count * sizeof(int));
        int *recv_data = calloc(element_count, sizeof(int));
        if (!test_data || !recv_data) {
            perror("buffer allocation failed");
            free(test_data);
            free(recv_data);
            continue;
        }

        for (size_t elem_idx = 0; elem_idx < element_count; ++elem_idx)
            test_data[elem_idx] = elem_idx + 100 * current_rank;

        double total_time = 0.0;

        for (int iter = 0; iter < NUM_ITER; ++iter) {
            struct timeval start, end;
            gettimeofday(&start, NULL);
            if (pg_all_reduce(test_data, recv_data, process_group_handle, element_count, DATA_INT, REDUCE_SUM) == -1) {
                printf("All-reduce operation failed\n");
            }
            gettimeofday(&end, NULL);
            double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
            total_time += elapsed;
        }

        double mbps = ((buf_size / 1e6) * NUM_ITER) / total_time;
        printf("Node %s (rank %d) Size: %zu bytes, Avg Time: %.6f s, Throughput: %.2f MB/s\n",
               local_hostname, current_rank, buf_size, total_time / NUM_ITER, mbps);

        free(test_data);
        free(recv_data);
        pg_close(process_group_handle);
    }


    return EXIT_SUCCESS;
}
