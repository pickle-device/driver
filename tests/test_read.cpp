// Copyright (c) 2025 The Regents of the University of California
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

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

  fd = open(pickle_driver_dev, O_RDONLY);

  if (fd < 0) {
    std::cerr << "failed to open " << pickle_driver_dev_str << std::endl;
    perror("Error");
    exit(errno);
  }

  if (read(fd, &content, content_size) != content_size) {
    std::cerr << "error while reading from " << pickle_driver_dev_str
              << std::endl;
    perror("Error");
    close(fd);
    exit(errno);
  }

  std::cout << "Content: 0x" << std::hex << content << std::dec << std::endl;
  close(fd);

  return 0;
}
