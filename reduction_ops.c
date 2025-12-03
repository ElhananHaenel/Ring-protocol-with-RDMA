#include "rdma_core.h"

/* Integer reduction operations */
void int_addition(void *target, const void *source, int elements) {
    int *dst_ptr = (int *) target;
    const int *src_ptr = (const int *) source;
    for (int idx = 0; idx < elements; ++idx) {
        dst_ptr[idx] += src_ptr[idx];
    }
}

void int_multiplication(void *target, const void *source, int elements) {
    int *dst_ptr = (int *) target;
    const int *src_ptr = (const int *) source;
    for (int idx = 0; idx < elements; ++idx) {
        dst_ptr[idx] *= src_ptr[idx];
    }
}


/* Double reduction operations */
void double_addition(void *target, const void *source, int elements) {
    double *dst_ptr = (double *) target;
    const double *src_ptr = (const double *) source;
    for (int idx = 0; idx < elements; ++idx) {
        dst_ptr[idx] += src_ptr[idx];
    }
}

void double_multiplication(void *target, const void *source, int elements) {
    double *dst_ptr = (double *) target;
    const double *src_ptr = (const double *) source;
    for (int idx = 0; idx < elements; ++idx) {
        dst_ptr[idx] *= src_ptr[idx];
    }
}

/* Lookup table mapping data types and operations to functions */
reduction_func_t reduction_table[DATA_TYPE_MAX][REDUCE_OP_MAX] = {
        [DATA_INT]    = {int_addition, int_multiplication},
        [DATA_DOUBLE] = {double_addition, double_multiplication}
};