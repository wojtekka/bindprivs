# $Id$

VERSION = 0.3-beta
CC = gcc
CFLAGS = -O3 -Wall -fomit-frame-pointer
MODULEDIR = /lib/modules/`uname -r`/misc
BINDIR = /usr/local/bin
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
	$(CC) bpset.c -o bpset

install:	bindprivs.o bpset
	install bindprivs.o $(MODULEDIR)
	install bpset $(BINDIR)
	install bpset.8 $(MANDIR)/man8
	install bindprivs.conf.5 $(MANDIR)/man5

tarball:	clean
	(cd ..; \
	mv bindprivs bindprivs-$(VERSION); \
	tar zcvf bindprivs-$(VERSION)/bindprivs-$(VERSION).tar.gz \
		--exclude bindprivs-$(VERSION)/RCS \
		--exclude bindprivs-$(VERSION)/TODO \
		--exclude bindprivs-$(VERSION)/reload \
		--exclude bindprivs-$(VERSION)/bindprivs.conf \
		--exclude bindprivs-$(VERSION)/bindprivs-$(VERSION).tar.gz \
		bindprivs-$(VERSION); \
	mv bindprivs-$(VERSION) bindprivs)

clean:
	rm -f *.o bpset *~ core bindprivs-*.tar.gz
