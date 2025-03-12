#!/bin/bash

# Copyright (c) 2025 The Regents of the University of California
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

sudo rmmod pickle_driver
sudo insmod build/pickle_driver.ko

sudo cp src/pickle_driver.h /usr/include/
