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
  uint64_t content[2];
  uint64_t content_size = 16;

  content[0] = 0xBADADD;
  content[1] = 0xBADC0FFEE;

  fd = open(pickle_driver_dev, O_RDWR);

  if (fd < 0) {
    std::cerr << "failed to open " << pickle_driver_dev_str << std::endl;
    perror("Error");
    exit(errno);
  }

  if (pwrite(fd, &content[0], 2, 0) != content_size) {
    std::cerr << "error while writing to " << pickle_driver_dev_str
              << std::endl;
    perror("Error");
    close(fd);
    exit(errno);
  }

  close(fd);

  return 0;
}
