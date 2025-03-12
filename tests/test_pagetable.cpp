// Copyright (c) 2025 The Regents of the University of California
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#include <fcntl.h>
#include <sys/ioctl.h>
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

  fd = open(pickle_driver_dev, O_RDONLY);

  if (fd < 0) {
    std::cerr << "failed to open " << pickle_driver_dev_str << std::endl;
    perror("Error");
    exit(errno);
  }

  params.pid = getpid();
  params.pagetable_paddr = 0;

  err = ioctl(fd, ARM64_IOC_PICKLE_DRIVER_GET_PROCESS_PAGETABLE_PADDR, &params);

  if (err) {
    std::cerr << "ARM64_IOC_PICKLE_DRIVER_GET_PROCESS_PAGETABLE_PADDR failed"
              << std::endl;
  }
  std::cout << "pid: " << params.pid << "; pagetable_paddr: 0x" << std::hex
            << params.pagetable_paddr << std::dec << std::endl;

  close(fd);

  return 0;
}
