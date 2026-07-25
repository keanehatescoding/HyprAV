obj-m += hello.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# Toolchain override for Clang-built kernels (e.g. CachyOS's -clang
# variant). A kernel module generally must be built with the same
# compiler family the target kernel itself was built with, especially
# under LTO/CFI configs. Usage:
#   make                       # default: GCC
#   make CC=clang LLVM=1       # build against a Clang-built kernel
CC   ?=
LLVM ?=

MAKE_ARGS := -C $(KDIR) M=$(PWD)
ifneq ($(CC),)
  MAKE_ARGS += CC=$(CC)
endif
ifneq ($(LLVM),)
  MAKE_ARGS += LLVM=$(LLVM)
endif

all:
	$(MAKE) $(MAKE_ARGS) modules

clean:
	$(MAKE) $(MAKE_ARGS) clean
