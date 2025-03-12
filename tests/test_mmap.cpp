// Copyright (c) 2025 The Regents of the University of California
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>

#include "pickle_driver.h"

int main() {
  const std::string pickle_driver_dev_str = "/dev/hey_pickle";
  const char* pickle_driver_dev = pickle_driver_dev_str.c_str();
  int fd;
  uint64_t content = 0;
  uint64_t content_size = sizeof(content);
  int err = 0;
  struct process_pagetable_params params;

  fd = open(pickle_driver_dev, O_RDWR | O_SYNC);

  if (fd < 0) {
    std::cerr << "failed to open " << pickle_driver_dev_str << std::endl;
    perror("Error");
    exit(errno);
  }

  uint8_t* mmap_ptr = (uint8_t*)mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                     MAP_FILE | MAP_SHARED, fd, 0);
  if (mmap_ptr == MAP_FAILED) {
    std::cerr << "Failed to open mmap for" << pickle_driver_dev_str
              << std::endl;
    perror("Error");
    close(fd);
    exit(1);
  }

  mmap_paddr_params mmap_params;
  mmap_params.mmap_id = 0;
  mmap_params.paddr = 0;

  err = ioctl(fd, ARM64_IOC_PICKLE_DRIVER_MMAP_PADDR, &mmap_params);
  if (err) {
    std::cerr << "Unsuccessfully retrieving physical address for mmap"
              << std::endl;
    perror("Error");
    close(fd);
    exit(errno);
  }

  std::cout << "mmap vaddr: 0x" << std::hex << (uint64_t)mmap_ptr << std::endl;
  std::cout << "mmap paddr: 0x" << std::hex << mmap_params.paddr << std::endl;
  ;

  close(fd);

  return 0;
}
