/*
 * bindprivs kernel module
 * (c) 1998-2002 wojtek kaniewski <wojtekka@dev.null.pl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
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

#include <linux/config.h>
#include <linux/types.h>
#if CONFIG_MODVERSIONS
#define MODVERSIONS
#include <linux/modversions.h>
#endif
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/errno.h>
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

/*
 * from net/socket.c
 */
#define MAX_SOCK_ADDR 128

/*
 * guess what? ;)
 */
struct bindpriv_entry *entries = NULL;
int entries_count = 0;

/*
 * syscall stuff
 */
extern void *sys_call_table[];
int (*old_socketcall)(int call, unsigned long *args);

/*
 * we have to lock, because rules can't change while in check_rule()
 */
rwlock_t __bp_lock = RW_LOCK_UNLOCKED;

/* 
 * we'd like to know if some socketcalls are happening.
 */
atomic_t __bp_socketcalls = ATOMIC_INIT(0);

/* 
 * used twice: in cleanup_module() and on IP_BINDPRIVS_UNLOAD 
 */
static inline void release_socketcall()
{
	unsigned long flags;

	save_flags(flags);
	cli();
	sys_call_table[__NR_socketcall] = old_socketcall;
	restore_flags(flags);
}

/* 
 * check if IPv4 matches.
 */
static inline int ipv4_match(struct in_addr x, struct in_addr addr, struct in_addr mask)
{
	return (x.s_addr & mask.s_addr) == addr.s_addr;
}

/* 
 * check whether IPv6 matches.
 */
static inline int ipv6_match(struct in6_addr x, struct in6_addr addr, struct in6_addr mask)
{
	return ((x.s6_addr32[0] & mask.s6_addr32[0]) == addr.s6_addr32[0]) &&
		((x.s6_addr32[1] & mask.s6_addr32[1]) == addr.s6_addr32[1]) &&
		((x.s6_addr32[2] & mask.s6_addr32[2]) == addr.s6_addr32[2]) &&
		((x.s6_addr32[3] & mask.s6_addr32[3]) == addr.s6_addr32[3]);
}

/*
 * is `a' a multiplicity of `b'? --stupid
 */
static inline int is_multiple(int a, int b)
{
	return (a / b * b == a);
}

/*
 * checks if current->uid and stuff match specified rule 
 */
static int user_matches(struct bindpriv_entry *e)
{
	int i, j;

	switch (e->bp_action) {
		case BP_ALLOW_UID:
		case BP_DENY_UID:
		case BP_FORCE_UID:
			
			if (!e->bp_uid_count)
				return 1;
			
			for (i = 0; i < e->bp_uid_count; i++)
				if (e->bp_uid[i] == current->uid)
					return 1;
			
			break;
			
		case BP_ALLOW_GID:
		case BP_DENY_GID:
		case BP_FORCE_GID:

			if (!e->bp_uid_count)
				return 1;
			
			for (i = 0; i < e->bp_uid_count; i++) {
				
					if (e->bp_uid[i] == current->gid)
						return 1;
					
					for (j = 0; j < current->ngroups; j++)
						if (e->bp_uid[i] == current->groups[j])
							return 1;
			}
			
			break;
	}

	return 0;
}

/*
 * check whether user is allowed to bind.
 */
static int bind_permitted(struct sockaddr *sa, int sa_len)
{
	struct bindpriv_entry *e = entries;
	int count = entries_count, res;

	/* if there are no bp rules, allow user to bind(). */
	if (!count || !e)
		return 1;

	/* verify parameters. */
	if (!sa || sa_len < sizeof(struct sockaddr))
		return 1;
	
	/* we're handling only IPv4 and IPv6 sockets. */
	if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)
		return 1;

	/* the default rule is to permit. */
	res = 1;

	/* iterate. */
	while (count--) {
		if (e->bp_family == AF_INET && sa->sa_family == AF_INET && ipv4_match(((struct sockaddr_in*) sa)->sin_addr, e->bp_addr, e->bp_mask))
			goto check_user;
		if (e->bp_family == AF_INET6 && sa->sa_family == AF_INET6 && ipv6_match(((struct sockaddr_in6*) sa)->sin6_addr, e->bp_addr6, e->bp_mask6))
			goto check_user;

		e++;
		continue;

	check_user:
		if (user_matches(e)) {
			res = (e->bp_action == BP_ALLOW_UID || e->bp_action == BP_ALLOW_GID);
			goto exit;
		}

		e++;
	}

exit:
	return res;
}

#if 0
/*
 * do we need to change to source address?
 */
static int force_address(int sock, struct sockaddr *sa, int sa_len)
{
	struct bindpriv_entry *e = entries;
	int count = entries_count, res;

	/* if there are no bp rules, do nothing. */
	if (!count || !e)
		return 0;

	/* verify parameters. */
	if (!sa || sa_len < sizeof(struct sockaddr))
		return 0;
	
	/* we're handling only IPv4 and IPv6 sockets. */
	if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)
		return 0;

	/* no error by default */
	res = 0;

	/* iterate. */
	while (count--) {
		if (e->bp_action != BP_FORCE_UID && e->bp_action != BP_FORCE_GID) {
			e++;
			continue;
		}

		if (user_matches(e)) {
			struct sockaddr_in sin;
			struct sockaddr_in6 sin6;
			struct sockaddr *sa = NULL;
			unsigned long args[3] = { sock, 0, 0 };
			mm_segment_t old_fs;
			
			printk("user matches\n");
			if (sa->sa_family == AF_INET) {
				sin.sin_family = AF_INET;
				sin.sin_port = 0;
				sin.sin_addr.s_addr = e->bp_addr.s_addr;
				args[1] = (unsigned long) &sin;
				args[2] = sizeof(sin);
			} else {
				sin6.sin6_family = AF_INET6;
				sin6.sin6_port = 0;
				sin6.sin6_flowinfo = 0;
				memcpy(&sin6.sin6_addr, &e->bp_addr6, sizeof(sin6.sin6_addr));
				args[1] = (unsigned long) &sin6;
				args[2] = sizeof(sin6);
			}

			old_fs = get_fs();
			set_fs(KERNEL_DS);
			printk("before bind\n");
			res = old_socketcall(SYS_BIND, args);
			printk("after bind\n");
			set_fs(old_fs);

			goto exit;
		}

		e++;
	}

exit:
	return res;
}
#endif

/*
 * self-descriptive.
 */
static asmlinkage int new_socketcall(int call, unsigned long *args)
{
	unsigned long a[5];
	char sockaddr[MAX_SOCK_ADDR];
	int res;

	atomic_inc(&__bp_socketcalls);
	MOD_INC_USE_COUNT;
	
	lock_kernel();
	
	if (call == SYS_CONNECT) {
		int sockaddr_len = sizeof(sockaddr);
		mm_segment_t old_fs = get_fs();
		unsigned long b[3];
		
		if (copy_from_user(a, args, 3 * sizeof(a[0]))) {
			res = -EFAULT;
			goto exit;
		}

		b[0] = a[0];
		b[1] = (unsigned long) sockaddr;
		b[2] = (unsigned long) &sockaddr_len;

		old_fs = get_fs();
		set_fs(KERNEL_DS);
		res = old_socketcall(SYS_GETSOCKNAME, b);
		set_fs(old_fs);

		if (res < 0)
			goto exit;

		read_lock(&__bp_lock);
		res = bind_permitted((struct sockaddr*) sockaddr, sockaddr_len);
		read_unlock(&__bp_lock);

		if (!res) {
			res = -EPERM;
			goto exit;
		}
	}
	
	if (call == SYS_SETSOCKOPT) {
		struct bindpriv_entry *new;
		int i;

		if (copy_from_user(a, args, 5 * sizeof(a[0]))) {
			res = -EFAULT;
			goto exit;
		}

		if (a[1] != IPPROTO_IP || (a[2] != IP_BINDPRIVS_SET && a[2] != IP_BINDPRIVS_UNLOAD))
			goto call;

		if (!capable(CAP_NET_ADMIN)) {
			res = -EPERM;
			goto exit;
		}

		if (a[2] == IP_BINDPRIVS_UNLOAD) {
			release_socketcall();
			res = 0;
			goto exit;
		}

		if (!is_multiple(a[4], sizeof(struct bindpriv_entry)) || (a[4] && !a[3])) {
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
					new[i].bp_action != BP_FORCE_UID &&
					new[i].bp_action != BP_ALLOW_GID &&
					new[i].bp_action != BP_DENY_GID &&
					new[i].bp_action != BP_FORCE_GID);
				
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
		
		if (entries) 
			kfree(entries);
		entries = new;
		entries_count = a[4] / sizeof(struct bindpriv_entry);

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

		if (!optlen || !a[3])
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

	MOD_DEC_USE_COUNT;
	atomic_dec(&__bp_socketcalls);
	
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
	
	return 0;
}

void cleanup_module()
{
	release_socketcall();
	
	if (atomic_read(&__bp_socketcalls)) {
		printk("bindprivs: %d socketcalls pending. RTFM. have a *nice* day.\n", atomic_read(&__bp_socketcalls));
		while (atomic_read(&__bp_socketcalls)) {
			current->policy |= SCHED_YIELD;
			schedule();
		}
	}
}

const static char spell[] = "\n"
"\n"
"\twlaz³ kotek na p³otek\n"
"\t\t\t\ti mruga,\n"
"\t³adna to piosenka\n"
"\t\t\t\tnie d³uga,\n"
"\tnie d³uga, nie krótka\n"
"\t\t\t\tlecz w sam raz,\n"
"\tza¶piewaj koteczku\n"
"\t\t\t\tjeszcze raz.\n"
"\n";

#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

