/*
 * bindprivs kernel module
 * (c) 1999-2002 wojtek kaniewski <wojtekka@dev.null.pl>
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

#ifndef __BINDPRIVS_H
#define __BINDPRIVS_H

/* we need struct in_addr and struct in6_addr */
#ifdef __KERNEL__
#include <linux/in.h>
#include <linux/in6.h>
#else
#include <netinet/in.h>
#endif

/* what do you know... the version */
#define VERSION "0.6-beta3"

/* default rules filename for bpset */
#define DEFAULT_FILENAME "/etc/bindprivs.conf"

/* optnames for setsockopt */
#define IP_BINDPRIVS_BASE 0xf400
#define IP_BINDPRIVS_GET (IP_BINDPRIVS_BASE+0)
#define IP_BINDPRIVS_SET (IP_BINDPRIVS_BASE+0)
#define IP_BINDPRIVS_UNLOAD (IP_BINDPRIVS_BASE+1)

/* maximum numbers of uid's/gid's in one rule */
#define BP_MAX_UID 16

/* bp_action values */
enum bindpriv_action {
	BP_ALLOW_UID = 0,
	BP_ALLOW_GID,
	BP_DENY_UID,
	BP_DENY_GID,
	BP_FORCE_UID,
	BP_FORCE_GID,
};

/* the structure for single entry. we're playing with an array of these. */
struct bindpriv_entry {
	int bp_action;
	int bp_uid_count;		/* 0 means any user or group */
	int bp_uid[BP_MAX_UID];
	int bp_family;			/* AF_INET or AF_INET6 */
	union {
		struct in_addr addr_u_4;
		struct in6_addr addr_u_6;
	} addr_u;
	union {
		struct in_addr mask_u_4;
		struct in6_addr mask_u_6;
	} mask_u;
#define bp_addr addr_u.addr_u_4
#define bp_addr6 addr_u.addr_u_6
#define bp_mask mask_u.mask_u_4
#define bp_mask6 mask_u.mask_u_6
};

#endif /* __BINDPRIVS_H */
