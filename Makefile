# $Id$

VERSION = 0.3-beta2
CC = gcc
CFLAGS = -O3 -Wall -fomit-frame-pointer
MODULEDIR = /lib/modules/`uname -r`/misc
SBINDIR = /usr/local/sbin
MANDIR = /usr/local/man
LINUX = /usr/src/linux

ifeq ($(LINUX)/.config, $(wildcard $(LINUX)/.config))
include $(LINUX)/.config
endif

ifdef CONFIG_SMP
CFLAGS:=$(CFLAGS) -D__SMP__
endif

all:	bindprivs.o bpset

bindprivs.o:	bindprivs.c bindprivs.h
	$(CC) $(CFLAGS) bindprivs.c -c -o bindprivs.o
	
	@echo "--------------------------------------------------------------------------"
	@echo "WARNING! This kernel module might HANG your machine. You have been warned."
	@echo "Author DOES NOT take ANY responsibility for any damages caused."
	@echo "--------------------------------------------------------------------------"

bpset:	bpset.c bindprivs.h
	$(CC) $(CFLAGS) bpset.c -o bpset

install:	bindprivs.o bpset
	install -m 644 bindprivs.o $(MODULEDIR)
	install -m 755 bpset $(SBINDIR)
	install -m 644 bpset.8 $(MANDIR)/man8
	install -m 644 bindprivs.conf.5 $(MANDIR)/man5

tarball:	clean
	./make-tarball.sh bindprivs bindprivs-$(VERSION)

clean:
	rm -f *.o bpset *~ core bindprivs-*.tar.gz
