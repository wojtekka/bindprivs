/*
 * bindprivs kernel module
 * (c) 1998-2001 wojtek kaniewski <wojtekka@dev.null.pl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *    
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* $Id$ */

#define __KERNEL__
#define MODULE
#define _LOOSE_KERNEL_NAMES

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#if CONFIG_MODVERSIONS
#include <linux/modversions.h>
#endif
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include "bindprivs.h"

/* from net/socket.c */
#define MAX_SOCK_ADDR 128

struct bindpriv_entry *entries = NULL;
int entries_count = 0;

/* syscall stuff */
extern void *sys_call_table[];
int (*old_socketcall)(int call, unsigned long *args);

/* we have to lock, because rules might change while in bind(). */
rwlock_t __bp_lock = RW_LOCK_UNLOCKED;

/* XXX we'd like to know if some socketcalls are happening. */
atomic_t __bp_socketcalls;

/* check if IPv4 matches. */
static inline int ipv4_match(struct in_addr x, struct in_addr addr, struct in_addr mask)
{
	return (x.s_addr & mask.s_addr) == addr.s_addr;
}

/* check whether IPv6 matches. */
static inline int ipv6_match(struct in6_addr x, struct in6_addr addr, struct in6_addr mask)
{
	return ((x.s6_addr32[0] & mask.s6_addr32[0]) == addr.s6_addr32[0]) &&
		((x.s6_addr32[1] & mask.s6_addr32[1]) == addr.s6_addr32[1]) &&
		((x.s6_addr32[2] & mask.s6_addr32[2]) == addr.s6_addr32[2]) &&
		((x.s6_addr32[3] & mask.s6_addr32[3]) == addr.s6_addr32[3]);
}

/* is `a' a multiplicity of `b'? --stupid */
static inline int is_multiple(int a, int b)
{
	return (a / b * b == a);
}

/* check whether user is allowed to bind. */
int bind_permitted(struct sockaddr *sa, int sa_len)
{
	struct bindpriv_entry *e = entries;
	int count = entries_count, i, j, res;

	/* if there are no bp rules, allow user to bind(). */
	if (!count || !e)
		return 1;

	/* check sa. */
	if (!sa || sa_len < sizeof(struct sockaddr))
		return 1;
	
	/* we're handling only IPv4 and IPv6 sockets. */
	if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)
		return 1;

	/* the default rule is to permit. */
	res = 1;

	/* iterate. */
	while (count--) {
		if (e->bp_family == AF_INET && ipv4_match(((struct sockaddr_in*) sa)->sin_addr, e->bp_addr, e->bp_mask))
			goto check;
		if (e->bp_family == AF_INET6 && ipv6_match(((struct sockaddr_in6*) sa)->sin6_addr, e->bp_addr6, e->bp_mask6))
			goto check;

		e++;
		continue;

	check:
		switch (e->bp_action) {
			case BP_ALLOW_UID:
			case BP_DENY_UID:
				if (!e->bp_uid_count) {
					res = (e->bp_action == BP_ALLOW_UID);
					goto exit;
				}
				for (i = 0; i < e->bp_uid_count; i++)
					if (e->bp_uid[i] == current->uid) {
						res = (e->bp_action == BP_ALLOW_UID);
						goto exit;
					} 
				break;
			case BP_ALLOW_GID:
			case BP_DENY_GID:
				if (!e->bp_uid_count) {
					res = (e->bp_action == BP_ALLOW_GID);
					goto exit;
				}
				for (i = 0; i < e->bp_uid_count; i++) {
					if (e->bp_uid[i] == current->gid) {
						res = (e->bp_action == BP_ALLOW_GID);
						goto exit;
					}
					for (j = 0; j < current->ngroups; j++)
						if (e->bp_uid[i] == current->groups[j]) {
							res = (e->bp_action == BP_ALLOW_GID);
							goto exit;
						}
				}
				break;
			default:
				goto exit;
		}

		e++;
	}

exit:
	return res;
}

int new_socketcall(int call, unsigned long *args)
{
	unsigned long a[5];
	char sockaddr[MAX_SOCK_ADDR];
	int res;

	atomic_inc(&__bp_socketcalls);	/* XXX */
	
	lock_kernel();
	
	if (call == SYS_BIND) {
		if (copy_from_user(a, args, 3 * sizeof(a[0]))) {
			res = -EFAULT;
			goto exit;
		}

		if (a[2] > MAX_SOCK_ADDR) {
			res = -EFAULT;
			goto exit;
		}

		if (copy_from_user(sockaddr, (void*) a[1], a[2])) {
			res = -EFAULT;
			goto exit;
		}

		read_lock(&__bp_lock);
		res = bind_permitted((struct sockaddr*) sockaddr, a[2]);
		read_unlock(&__bp_lock);

		if (!res) {
			res = -EPERM;
			goto exit;
		}
	}
	
	if (call == SYS_SETSOCKOPT) {
		struct bindpriv_entry *tmp, *new;
		int i;
		
		if (copy_from_user(a, args, 5 * sizeof(a[0]))) {
			res = -EFAULT;
			goto exit;
		}

		if (a[1] != IPPROTO_IP || a[2] != IP_BINDPRIVS_SET)
			goto call;
		
		if (!capable(CAP_NET_ADMIN)) {
			res = -EPERM;
			goto exit;
		}

		if (!is_multiple(a[4], sizeof(struct bindpriv_entry))) {
			res = -EINVAL;
			goto exit;
		}

		new = NULL;

		if (a[4]) {					
			new = kmalloc(a[4], GFP_KERNEL);
			if (copy_from_user(new, (void*) a[3], a[4])) {
				kfree(new);
				res = -EFAULT;
				goto exit;
			}
			
			/* verify the table. */
			for (i = 0; i < a[4] / sizeof(struct bindpriv_entry); i++) {
				int invalid = 0;
				
				invalid = (new[i].bp_action != BP_ALLOW_UID &&
					new[i].bp_action != BP_DENY_UID &&
					new[i].bp_action != BP_ALLOW_GID &&
					new[i].bp_action != BP_DENY_GID);
				
				invalid |= (new[i].bp_uid_count < 0 ||
					new[i].bp_uid_count > BP_MAX_UID);
					
				invalid |= (new[i].bp_family != AF_INET &&
					new[i].bp_family != AF_INET6);
				
				if (invalid) {
					kfree(new);
					res = -EINVAL;
					goto exit;
				}
			}
		}

		write_lock(&__bp_lock);
		
		tmp = entries;
		entries = new;
		entries_count = a[4] / sizeof(struct bindpriv_entry);
		if (!tmp)
			kfree(tmp);

		write_unlock(&__bp_lock);
    		
		res = 0;
		goto exit;
	}
	
	if (call == SYS_GETSOCKOPT) {
		int optlen;

		if (copy_from_user(a, args, 5 * sizeof(a[0]))) {
			res = -EFAULT;
			goto exit;
		}

		if (a[1] != IPPROTO_IP || a[2] != IP_BINDPRIVS_GET)
			goto call;

		if (!capable(CAP_NET_ADMIN)) {
			res = -EPERM;
			goto exit;
		}

		if (copy_from_user(&optlen, (void*) a[4], sizeof(optlen))) {
			res = -EFAULT;
			goto exit;
		}

		if (!optlen && !a[3])
			optlen = entries_count;
		else {
			if (optlen > entries_count * sizeof(*entries))
				optlen = entries_count * sizeof(*entries);
			if (optlen) {
				read_lock(&__bp_lock);
				res = copy_to_user((void*) a[3], entries, optlen);
				read_unlock(&__bp_lock);

				if (res) {
					res = -EFAULT;
					goto exit;
				}
			}
		}

		if (copy_to_user((void*) a[4], &optlen, sizeof(optlen))) {
			res = -EFAULT;
			goto exit;
		}

		res = 0;
		goto exit;		
	}

call:
	res = old_socketcall(call, args);
exit:
	unlock_kernel();

	atomic_dec(&__bp_socketcalls);	/* XXX */
	
	return res;
}

int init_module()
{
	unsigned long flags;

	atomic_set(&__bp_socketcalls, 0);
	
	save_flags(flags);
	cli();
	old_socketcall = sys_call_table[__NR_socketcall];
	sys_call_table[__NR_socketcall] = new_socketcall;
	restore_flags(flags);
	
	return 0;
}

void cleanup_module()
{
	unsigned long flags;
	
	save_flags(flags);
	cli();
	sys_call_table[__NR_socketcall] = old_socketcall;
	restore_flags(flags);
	
	/* XXX */
	if (atomic_read(&__bp_socketcalls)) {
		printk("bindprivs: %d socketcalls pending.\n", atomic_read(&__bp_socketcalls));
		while (atomic_read(&__bp_socketcalls))
			schedule();
	}
}

const static char spell[] = "

fnord.

";