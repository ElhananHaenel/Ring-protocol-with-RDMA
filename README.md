# Ring-protocol-with-RDMA

A high-performance RDMA (Remote Direct Memory Access) implementation of collective communication operations using ring topology for distributed computing systems. This project implements `AllReduce` and other collective operations on a ring of nodes connected via InfiniBand.

## Overview

This project provides an educational implementation of distributed collective operations using RDMA over InfiniBand. It demonstrates:

- **Ring Topology Communication**: Direct peer-to-peer connections between neighboring nodes in a logical ring.
- **RDMA Operations**: Zero-copy data transfers using InfiniBand Verbs API.
- **Collective Operations**: AllReduce and AllGather implementations optimized for ring topologies.
- **Double Buffering**: Efficient buffer management to overlap computation and communication.
- **Reduction Operations**: Support for various data types (int, double) and operations (sum, multiplication).

## Project Structure

### Core Files

| File | Purpose |
|------|---------|
| `rdma_core.h` | Header file defining all data structures and API interfaces |
| `connection_mgmt.c` | Establishes and manages InfiniBand connections between nodes |
| `network_exchange.c` | Handles TCP metadata exchange for RDMA setup |
| `rdma_operations.c` | Implements low-level RDMA operations and work request processing |
| `collective_ops.c` | High-level collective operations (AllReduce, AllGather) |
| `reduction_ops.c` | Reduction operation implementations for different data types |
| `test_application.c` | Benchmark application for performance testing |

## Compilation

### Prerequisites

- **Ubuntu/Debian**:
  ```bash
  sudo apt-get install libibverbs-dev librdmacm-dev
  ```

### Build

```bash
gcc -o test_application \
    test_application.c \
    collective_ops.c \
    connection_mgmt.c \
    network_exchange.c \
    rdma_operations.c \
    reduction_ops.c \
    -lpthread -libverbs -lrdmacm -O2
```


## Usage

### Basic Execution

Run on a single node (for testing):
```bash
./test_application -myindex 0 -list localhost localhost localhost
```

### Distributed Execution

On **Node 0** (rank 0):
```bash
./test_application -myindex 0 -list node0 node1 node2 node3
```

On **Node 1** (rank 1):
```bash
./test_application -myindex 1 -list node0 node1 node2 node3
```

On **Node 2** (rank 2):
```bash
./test_application -myindex 2 -list node0 node1 node2 node3
```

On **Node 3** (rank 3):
```bash
./test_application -myindex 3 -list node0 node1 node2 node3
```

### Command Line Arguments

- `-myindex <rank>`: Rank of this node (0 to N-1)
- `-list <node1> <node2> ... <nodeN>`: List of all node hostnames/IPs


## Requirements

- **Hardware**: RDMA-capable network adapter (InfiniBand or RoCE)
- **OS**: Linux (tested on Ubuntu 20.04+, RHEL 8+)
- **Libraries**:
  - libibverbs (InfiniBand Verbs API)
  - librdmacm (RDMA Connection Manager)
  - POSIX pthreads
- **C Standard**: C99 or later
- **Compiler**: GCC 7.0+


This project is for educational use only.

