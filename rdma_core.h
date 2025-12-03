#ifndef RDMA_CORE_H
#define RDMA_CORE_H

#include <infiniband/verbs.h>

/* Maximum number of data buffers for double buffering */
#define DATA_BUFFER_COUNT 2

/* Supported data types for collective operations */
typedef enum {
    DATA_INT,
    DATA_DOUBLE,
    DATA_TYPE_MAX
} data_type_t;

/* Available reduction operations */
typedef enum {
    REDUCE_SUM,
    REDUCE_MULT,
    REDUCE_OP_MAX
} reduce_op_t;

/* Work request identifiers for completion tracking */
typedef enum {
    WR_RECV = 1ULL,
    WR_SEND = 2ULL,
    WR_READ = 3ULL,
} work_request_id_t;


/* Function pointer type for reduction operations */
typedef void (*reduction_func_t)(void *target, const void *source, int elements);

extern reduction_func_t reduction_table[DATA_TYPE_MAX][REDUCE_OP_MAX];

/* Parameters for establishing IB connections */
struct ib_conn_params {
    int local_id; /* Local Identifier (LID) */
    int qp_number; /* Queue Pair Number */
    int packet_seq_num; /* Packet Sequence Number for reliable connections */
    union ibv_gid global_id; /* Global Identifier for RoCE */
};

/* Metadata for RDMA rendezvous protocol */
struct rdma_metadata {
    uintptr_t buffer_addr; /*Remote buffer address for RDMA operations.*/
    uint32_t remote_key; /*Remote memory region key for access permissions.*/
    int data_size; /*Size of the data to be transferred.*/
};

/* InfiniBand connection structure for peer communication */
struct ib_connection {
    struct ibv_comp_channel *completion_ch; /*Event channel for completion notifications.*/
    struct ibv_mr *buffer_mr; /*Memory region for message buffer registration.*/
    struct ibv_cq *completion_q; /*Completion queue for tracking work completions.*/
    struct ibv_qp *queue_pair; /*The actual communication channel (QP) to this peer.*/
    struct rdma_metadata *message_buf; /*Pre-allocated buffer for sending/receiving metadata.*/
    int message_size; /*Size of each message in the buffer (metadata size).*/
    int queue_depth; /*Depth of the completion queue and buffer (number of messages).*/
    int pending_receives; /*Count of posted but uncompleted receive requests.*/
    struct ibv_port_attr port_info; /*Attributes of the local IB port.*/
    size_t buffer_idx; /*Index for circular buffer management.*/
};


/* Process group handle containing all connection information */
struct process_group {
    struct ibv_context *ib_ctx; /*A handle to the physical InfiniBand device itself.*/
    struct ibv_pd *protection_domain; /*The single Protection Domain for all our resources.*/
    struct ib_connection *left_peer; /*Connection to the left neighbor in the ring topology.*/
    struct ib_connection *right_peer; /*Connection to the right neighbor in the ring topology.*/
    int total_nodes;
    int node_rank;
    struct ibv_mr *buffer_mrs[DATA_BUFFER_COUNT]; /*Memory regions for double buffering during operations.*/
};


/* Core API functions */
int connect_process_group(int node_rank, void **group_handle, const char **node_list, int node_count);

int pg_all_reduce(void *send_data, void *recv_data, void *group_handle, int element_count, data_type_t dtype,
                  reduce_op_t operation);

int execute_all_gather(void *source_buffer, void *result_buffer, void *group_handle, const int element_size,
                       const size_t chunk_size, const data_type_t data_type);

int execute_reduce_scatter(void *source_buffer, void *result_buffer,
                           const int element_size, const size_t chunk_size,
                           void *group_handle, const data_type_t data_type,
                           const reduce_op_t reduction_op);

int pg_close(void *group_handle);

/* Function declarations for specific reduction operations */
void int_addition(void *target, const void *source, int elements);

void int_multiplication(void *target, const void *source, int elements);

void double_addition(void *target, const void *source, int elements);

void double_multiplication(void *target, const void *source, int elements);

int allocate_ib_resources(struct process_group **group_handle);

int execute_reduce_scatter(void *source_buffer, void *result_buffer,
                           const int element_size, const size_t chunk_size,
                           void *group_handle, const data_type_t data_type,
                           const reduce_op_t reduction_op);

#endif /* RDMA_CORE_H */