# Copyright (c) 2025 The Regents of University of California
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

obj-m += pickle_driver.o

PWD := $(CURDIR)


all:
	# this is for gem5 in which we use an external linux kernel
	make -C /home/ubuntu/linux_src/ M=$(PWD) modules

debug:
	# this is for ubuntu in which we use a kernel on the disk
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	# this is for gem5 in which we use an external linux kernel
	make -C /home/ubuntu/linux_src/ M=$(PWD) clean

clean-debug:
	# this is for ubuntu in which we use a kernel on the disk
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
