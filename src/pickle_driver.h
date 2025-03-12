// Copyright (c) 2025 The Regents of University of California
// All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only

// Functions and structure available to both kernel and user

#ifndef PICKLE_DRIVER_HEADER
#define PICKLE_DRIVER_HEADER

#include <linux/types.h>

struct process_pagetable_params {
  uint64_t pid;              // input
  uint64_t pagetable_paddr;  // output
};

struct mmap_paddr_params {
  uint64_t mmap_id;  // input
  uint64_t paddr;    // output
};

#define ARM64_IOC_PICKLE_DRIVER_MMAP_PADDR \
  _IOWR('c', 0x1, struct mmap_paddr_params)
#define ARM64_IOC_PICKLE_DRIVER_GET_PROCESS_PAGETABLE_PADDR \
  _IOR('c', 0x2, struct process_pagetable_params)

#endif  // PICKLE_DRIVER_HEADER
