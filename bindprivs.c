/*
 * bindprivs v0.01
 * (c) copyright 1999 by wojtek kaniewski <wojtekka@irc.pl>
 */

#define MODULE
#define __KERNEL__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/errno.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>
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
  
  if (copy_from_user(a, args, 3 * sizeof(unsigned long)))
    return -EFAULT;
    
  if (call == SYS_BIND) {
    if (copy_from_user(sa, (void*) a[1], (a[2] > 256) ? 256 : a[2]))
      return -EFAULT;
    if (check_bind((struct sockaddr*) &sa, a[2]))
      return -EPERM;
  }
  
  return old_socketcall(call, args);
}

int init_module()
{
  printk("bindprivs loaded, %d entries\n", ENTRIES);
  old_socketcall = sys_call_table[__NR_socketcall];
  sys_call_table[__NR_socketcall] = new_socketcall;
  return 0;
}

void cleanup_module()
{
  sys_call_table[__NR_socketcall] = old_socketcall;
}
