/*
 * bindprivs v0.02b
 * (c) copyright 1999, 2001 by wojtek kaniewski <wojtekka@irc.pl>
 */

#ifndef __BINDPRIVS_H
#define __BINDPRIVS_H

/*
 * kernel version dependencies stolen from lcamtuf's afhrm
 * http://dione.ids.pl/~lcamtuf/pliki.html
 */

#include <linux/version.h>

#if LINUX_VERSION_CODE < 0x020100
#  define KERNEL_DESC "2.0"
#  include <asm/segment.h>
#  define lock_kernel() do { } while(0)
#  define unlock_kernel() do { } while(0)
#  define copy_to_user(t,f,n) (memcpy_tofs(t,f,n), 0)
#  define copy_from_user(t,f,n) (memcpy_fromfs((t),(f),(n)), 0)
#else
#  define KERNEL_DESC "2.2"
#  include <linux/smp_lock.h>
#  include <asm/uaccess.h>
#  include <asm/io.h>
#endif

/*
 * configuration stuff
 */

enum {
  ALLOW_USERS,
  ALLOW_GROUPS,
  DENY_USERS,
  DENY_GROUPS
};

struct bindprivs_entry {
  int action;
  unsigned long addr;
  unsigned long mask;
  int *uids;
};

#include "config.h"

#endif __BINDPRIVS_H