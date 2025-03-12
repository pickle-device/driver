#!/bin/bash

# Copyright (c) 2025 The Regents of the University of California
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

mkdir build
cd src
make clean-debug
make debug
cp pickle_driver.ko ../build/
cd ../
