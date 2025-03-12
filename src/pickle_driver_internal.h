// Copyright (c) 2025 The Regents of the University of California
// All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only

#ifndef PICKLE_DRIVER_INTERNAL_HEADER
#define PICKLE_DRIVER_INTERNAL_HEADER

#include <linux/types.h>

#include "pickle_driver.h"

const size_t MAX_NUM_ITEMS = 1024;

struct mmap_paddr_tracker {
  phys_addr_t* paddrs;
  uint64_t array_size;
};

void mmap_paddr_tracker_init(struct mmap_paddr_tracker* tracker) {
  size_t i = 0;
  tracker->paddrs =
      kmalloc_array(MAX_NUM_ITEMS, sizeof(phys_addr_t), GFP_KERNEL);
  tracker->array_size = MAX_NUM_ITEMS;
  for (i = 0; i < tracker->array_size; i++) {
    tracker->paddrs[i] = 0ULL;
  }
}

void mmap_paddr_tracker_free(struct mmap_paddr_tracker* tracker) {
  kfree(tracker->paddrs);
  tracker->array_size = 0;
}

#endif  // PICKLE_DRIVER_INTERNAL_HEADER
