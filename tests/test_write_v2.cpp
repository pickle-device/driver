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

#include "gem5/m5ops.h"
#include "m5_mmap.h"
#include "pickle_driver.h"

int main() {
  map_m5_mem();
  const std::string pickle_driver_dev_str = "/dev/hey_pickle";
  const char* pickle_driver_dev = pickle_driver_dev_str.c_str();
  int fd;
  uint64_t content[2];
  uint64_t content_size = 16;

  content[0] = 1;
  content[1] = 16;

  fd = open(pickle_driver_dev, O_RDWR);

  if (fd < 0) {
    std::cerr << "failed to open " << pickle_driver_dev_str << std::endl;
    perror("Error");
    exit(errno);
  }

  m5_exit_addr(0);
  int sum = 0;
  for (int i = 0; i < 30; i++) sum += i;
  std::cout << sum << std::endl;

  if (pwrite(fd, &content[0], 2, 0) != content_size) {
    std::cerr << "error while writing to " << pickle_driver_dev_str
              << std::endl;
    perror("Error");
    close(fd);
    exit(errno);
  }

  uint64_t content2[2];
  content2[0] = 0xBADADD;
  content2[1] = 0xBADC0FFEE;

  if (pwrite(fd, &content2[0], 16, 1) != content_size) {
    std::cerr << "error while writing offset 1 to " << pickle_driver_dev_str
              << std::endl;
    perror("Error");
    close(fd);
    exit(errno);
  }

  close(fd);

  return 0;
}
