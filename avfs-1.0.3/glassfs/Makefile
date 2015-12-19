#CC=gcc
#CFLAGS=-Wall -W

obj-m := glassfs.o redir2.o

#KERNDIR := /store/linux/uml/linux-2.6.4
#EXTRA := ARCH=um
ifeq ($(KERNELDIR),)
  KERNDIR := $(shell cd /lib/modules/`uname -r`/build; /bin/pwd)
else
  KERNDIR := ${KERNELDIR}
endif

all:
	$(MAKE) -C $(KERNDIR) SUBDIRS=$(PWD) $(EXTRA) modules

clean:
	rm -f *~
	rm -f *.o *.ko *.mod.c .*.cmd
