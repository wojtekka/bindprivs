/*
 * bindprivs v0.02b
 * (c) copyright 1999, 2001 by wojtek kaniewski <wojtekka@irc.pl>
 */

#define MODULE
#define __KERNEL__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#if CONFIG_MODVERSIONS
#include <linux/modversions.h>
#endif
//#include <linux/string.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <asm/unistd.h>
#include "bindprivs.h"

extern void *sys_call_table[];

int (*old_socketcall)(int call, unsigned long *args);

int check_bind(struct sockaddr *sa, int salen)
{
  struct bindprivs_entry *e;
  unsigned long addr;
  int x, uid, *y, z;
  
  if (sa->sa_family != AF_INET)
    return 0;

  addr = ((struct sockaddr_in*) sa)->sin_addr.s_addr;
  uid = current->uid;

  for (x = 0; x < ENTRIES; x++) {
    e = &bindprivs_config[x];
    if (e->addr != (addr & e->mask))
      continue;
    switch (e->action) {
      case ALLOW_USERS:
      case DENY_USERS:
        if (!(y = e->uids))
	  return (e->action == DENY_USERS);
	for (; *y != -1; y++)
	  if (uid == *y)
	    return (e->action == DENY_USERS);
	break;
      case ALLOW_GROUPS:
      case DENY_GROUPS:
        if (!(y = e->uids))
	  return (e->action == DENY_GROUPS);
	for (; *y != -1; y++)
	  for (z = 0; z < 10; z++)
	    if (current->groups[z] == *y)
  	      return (e->action == DENY_GROUPS);
	break;
    }
  }
    
  return 0;
}

int new_socketcall(int call, unsigned long *args)
{
  unsigned long a[3];
  char sa[256];
  int res;

  lock_kernel();
    
  if (copy_from_user(a, args, 3 * sizeof(unsigned long))) {
    res = -EFAULT;
    goto exit;
  }    
  if (call == SYS_BIND) {
    if (copy_from_user(sa, (void*) a[1], (a[2] > 256) ? 256 : a[2])) {
      res = -EFAULT;
      goto exit;
    }
    if (check_bind((struct sockaddr*) &sa, a[2])) {
      res = -EPERM;
      goto exit;
    }
  }
  res = old_socketcall(call, args);
exit:
  unlock_kernel();
  
  return res;
}

int init_module()
{
  unsigned long flags;

  save_flags(flags);
  cli();
  old_socketcall = sys_call_table[__NR_socketcall];
  sys_call_table[__NR_socketcall] = new_socketcall;
  restore_flags(flags);
  printk("bindprivs for " KERNEL_DESC" loaded, %d entries\n", ENTRIES);

  return 0;
}

void cleanup_module()
{
  unsigned long flags;

  save_flags(flags);
  cli();
  sys_call_table[__NR_socketcall] = old_socketcall;
  restore_flags(flags);
}
