/*
 * bindprivs access list manager
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <getopt.h>
#include "bindprivs.h"

char *uid_to_name(uid_t uid)
{
	struct passwd *pw = getpwuid(uid);
	static char tmp[64];
	
	if (!pw)
		sprintf(tmp, "%d", uid);
	else
		strncpy(tmp, pw->pw_name, sizeof(tmp));
	
	return tmp;
}

char *gid_to_name(gid_t gid)
{
	struct group *gr = getgrgid(gid);
	static char tmp[64];
	
	if (!gr)
		sprintf(tmp, "%d", gid);
	else
		strncpy(tmp, gr->gr_name, sizeof(tmp));
	
	return tmp;
}

int mask_to_num(unsigned int mask)
{
	int i, j;
	
	if (mask == 0xffffffff)
		return 32;
	for (i = 0, j = 1; i < 32; i++, j *= 2)
		if (mask == j - 1)
			return i;
	return -1;
}

unsigned int num_to_mask(int num)
{
	int i, j;
	
	if (num > 31)
		return 0xffffffff;

	for (i = 0, j = 1; i < num; i++)
		j *= 2;
		
	return j - 1;
}

int isnum(char *buf)
{
	for(; *buf; buf++)
		if (!isdigit(*buf))
			return 0;
	return 1;
}

#define IPV6_IS_ZERO(x) (!(x).s6_addr32[0] && !(x).s6_addr32[1] && !(x).s6_addr32[2] && !(x).s6_addr32[3])

char *addr_to_name(struct bindpriv_entry *e)
{
	static char tmp[128];
	
	if (e->bp_family == AF_INET) {
		int m = mask_to_num(e->bp_mask.s_addr);
		
		if (!e->bp_addr.s_addr && !e->bp_mask.s_addr)
			sprintf(tmp, "any");
		else {
			strcpy(tmp, inet_ntoa(e->bp_addr));
			if (m == -1)
				sprintf(tmp + strlen(tmp), "/%s", inet_ntoa(e->bp_mask));
			else if (m != 32)
				sprintf(tmp + strlen(tmp), "/%d", m);
		}
	} else {
		if (IPV6_IS_ZERO(e->bp_addr6) && IPV6_IS_ZERO(e->bp_mask6))
			sprintf(tmp, "any6");
		else {
			int m[4], i, queer, valid, sum;
			
			inet_ntop(AF_INET6, &e->bp_addr6, tmp, sizeof(tmp));

			for (i = 0, sum = 0; i < 4; i++) {
				m[i] = mask_to_num(e->bp_mask6.s6_addr32[i]);
				sum += m[i];
			}

			queer = (m[0] == -1 || m[1] == -1 || m[2] == -1 || m[3] == -1);
			valid = ((m[0] < 32 && !m[1] && !m[2] && !m[3]) ||
				(m[0] == 32 && m[1] < 32 && !m[2] && !m[3]) ||
				(m[0] == 32 && m[1] == 32 && !m[2] < 32 && !m[3]) ||
				(m[0] == 32 && m[2] == 32 && m[3] == 32));
			
			if (queer || !valid) {
				strcat(tmp, "/");
				inet_ntop(AF_INET6, &e->bp_mask6, tmp + strlen(tmp), sizeof(tmp) - strlen(tmp) - 1);
			} else if (sum != 128)
				snprintf(tmp + strlen(tmp), sizeof(tmp) - strlen(tmp) - 1, "/%d", sum);
		}			
	}
	
	return tmp;
}

int list_rules()
{
	int count = 0, len = 0, i, j;
	struct bindpriv_entry *e;
	
	if (getsockopt(0, IPPROTO_IP, IP_BINDPRIVS_GET, NULL, &count)) {
		perror("getsockopt");
		return 1;
	}

	len = count * sizeof(struct bindpriv_entry);
	if (!(e = (void*) malloc(len))) {
		perror("malloc");
		return 1;
	}
	
	if (getsockopt(0, IPPROTO_IP, IP_BINDPRIVS_GET, e, &len)) {
		perror("getsockopt");
		return 1;
	}
	
	for (i = 0; i < count; i++) {
		printf("%s%s %s",
			(e[i].bp_action == BP_ALLOW_UID ||
			e[i].bp_action == BP_ALLOW_GID) ? "allow" : "deny",
			(e[i].bp_action == BP_ALLOW_GID ||
			e[i].bp_action == BP_DENY_GID) ? "group" : "",
			addr_to_name(&e[i]));
		if (e[i].bp_uid_count) {
			for (j = 0; j < e[i].bp_uid_count; j++) {
				printf(" %s", (e[i].bp_action == BP_ALLOW_UID
					|| e[i].bp_action == BP_DENY_UID) ?
					uid_to_name(e[i].bp_uid[j]) :
					gid_to_name(e[i].bp_uid[j]));
			}
		} else
			printf(" any");
		printf("\n");
	}

	return 0;
}

int set_rules(char *filename)
{
	FILE *f;
	char buf[1024];
	int line = 0, count = 0;
	struct bindpriv_entry *entries = NULL;
	
	if (!(f = fopen(filename, "r"))) {
		perror(filename);
		return 1;
	}
	
	while (line++, fgets(buf, sizeof(buf)-1, f)) {
		char *t;
		int tokens;
		struct bindpriv_entry e;
		
		if (buf[strlen(buf)-1] == '\n')
			buf[strlen(buf)-1] = 0;
		else {
			if (!feof(f)) {
				fprintf(stderr, "%s: line %d: line too long\n", filename, line);
				fclose(f);
				return 1;
			}
			fprintf(stderr, "%s: line %d: warning: no newline at end of file\n", filename, line);
		}
		if (buf[0] == '#' || (buf[0] == '/' && buf[1] == '/'))
			continue;

		t = strtok(buf, " \t");
		tokens = 0;
		e.bp_uid_count = 0;
		while (t) {
			if (*t == '#' || (*t && *t == '/' && *(t+1) == '/'))
				break;
			if (tokens == 0) {
				if (!strcasecmp(t, "allow"))
					e.bp_action = BP_ALLOW_UID;
				else if (!strcasecmp(t, "deny"))
					e.bp_action = BP_DENY_UID;
				else if (!strncasecmp(t, "allowgroup", 10))
					e.bp_action = BP_ALLOW_GID;
				else if (!strncasecmp(t, "denygroup", 9))
					e.bp_action = BP_DENY_GID;
				else {
					fprintf(stderr, "%s: line %d: unknown rule action\n", filename, line);
					fclose(f);
					free(entries);
					return 1;
				}
			}
			if (tokens == 1) {
				if (!strcasecmp(t, "any") || !strcasecmp(t, "all")) {
					e.bp_addr.s_addr = 0;
					e.bp_mask.s_addr = 0;
					e.bp_family = AF_INET;
				} else if (!strcasecmp(t, "any6") || !strcasecmp(t, "all6")) {
					inet_pton(AF_INET6, "::", &e.bp_addr6);
					inet_pton(AF_INET6, "::", &e.bp_mask6);
					e.bp_family = AF_INET6;
				} else {
					char *mask = NULL;
					
					if (strchr(t, '/')) {
						mask = strchr(t, '/') + 1;
						*(mask - 1) = 0;
					}
					if (strchr(t, ':')) {
						e.bp_family = AF_INET6;
						
						if (inet_pton(AF_INET6, t, &e.bp_addr6) < 0) {
							fprintf(stderr, "%s: line %d: invalid address\n", filename, line);
							fclose(f);
							free(entries);
							return 1;
						}
						if (!mask)
							inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &e.bp_mask6);
						else {
							if (isnum(mask)) {
								int m = atoi(mask);
								
			    					inet_pton(AF_INET6, "::", &e.bp_mask6);
								if (m <= 32)
									e.bp_mask6.s6_addr32[0] = num_to_mask(m);
								else if (m <= 64) {
									e.bp_mask6.s6_addr32[0] = 0xffffffff;
									e.bp_mask6.s6_addr32[1] = num_to_mask(m - 32);
								} else if (m <= 96) {
									e.bp_mask6.s6_addr32[0] = 0xffffffff;
									e.bp_mask6.s6_addr32[1] = 0xffffffff;
									e.bp_mask6.s6_addr32[2] = num_to_mask(m - 64);
								} else {
									e.bp_mask6.s6_addr32[0] = 0xffffffff;
									e.bp_mask6.s6_addr32[1] = 0xffffffff;
									e.bp_mask6.s6_addr32[2] = 0xffffffff;
									e.bp_mask6.s6_addr32[3] = num_to_mask(m - 96);
								}
							} else if (inet_pton(AF_INET6, mask, &e.bp_mask6) < 0) {
								fprintf(stderr, "%s: line %d: invalid mask\n", filename, line);
								fclose(f);
								free(entries);
								return 1;
							}
						}
					} else {
						e.bp_family = AF_INET;
						
						if (!inet_aton(t, &e.bp_addr)) {
							fprintf(stderr, "%s: line %d: invalid address\n", filename, line);
							fclose(f);
							free(entries);
							return 1;
						}
						if (!mask)
							e.bp_mask.s_addr = 0xffffffff;
						else {
							if (isnum(mask))
								e.bp_mask.s_addr = num_to_mask(atoi(mask));
							else if (!inet_aton(mask, &e.bp_mask)) {
								fprintf(stderr, "%s: line %d: invalid mask\n", filename, line);
								fclose(f);
								free(entries);
								return 1;
							}
						}
					}
					/* let's make strtok() happy. */
					if (mask)
						*(mask - 1) = '/';
				}
			}
			if (tokens > 1) {
				int uid;

				if (!strcasecmp(t, "any") || !strcasecmp(t, "all"))
					e.bp_uid_count = 0;
				else {
					if (e.bp_uid_count == BP_MAX_UID) {
						fprintf(stderr, "%s: line %d: too many %s\n", filename, line, (e.bp_action == BP_ALLOW_UID || e.bp_action == BP_DENY_UID) ? "users" : "groups");
						fclose(f);
						free(entries);
						return 1;
					}
					if (e.bp_action == BP_DENY_UID || e.bp_action == BP_ALLOW_UID) {
						struct passwd *pw = getpwnam(t);
						
						if (isnum(t))
							uid = atoi(t);
						else if (pw)
							uid = pw->pw_uid;
						else {
							fprintf(stderr, "%s: %d: unknown user '%s'\n", filename, line, t);
							fclose(f);
							free(entries);
							return 1;
						}
					} else {
						struct group *gr = getgrnam(t);
		    			
						if (isnum(t))
							uid = atoi(t);
						else if (gr)
							uid = gr->gr_gid;
						else {
							fprintf(stderr, "%s: %d: unknown group '%s'\n", filename, line, t);
							fclose(f);
							free(entries);
							return 1;
						}
					}
			
					e.bp_uid[e.bp_uid_count++] = uid;
				}
			}

			t = strtok(NULL, " \t");
			tokens++;
		}
		
		if (tokens == 1) {
			fprintf(stderr, "%s: line %d: missing address\n", filename, line);
			fclose(f);
			free(entries);
			return 1;
		}
		
		if (tokens == 2)
			fprintf(stderr, "%s: line %d: warning: no %s specified -- assuming 'any'\n", filename, line, (e.bp_action == BP_ALLOW_UID || e.bp_action == BP_DENY_UID) ? "users" : "groups");
		
		if (tokens > 1) {
			count++;
			if (!(entries = realloc(entries, count * sizeof(struct bindpriv_entry)))) {
				perror("malloc");
				fclose(f);
				return 1;
			}
			memcpy(&entries[count - 1], &e, sizeof(e));
		}
	}	
	
	fclose(f);
	
	if (setsockopt(0, IPPROTO_IP, IP_BINDPRIVS_SET, entries, count * sizeof(struct bindpriv_entry))) {
		perror("setsockopt");
		free(entries);
		return 1;
	}
	
	free(entries);
	
	return 0;
}

void usage(char *name)
{
	printf("\
Usage: %s [OPTION]...
Manage bind(2) access rules.

  -s, --set[=FILE]   Read and set new rules (see bindprivs(5) for details)
  -l, --list         List rules
  
  -h, --help         Give this help list
  -V, --version      Print program version
  
The default filename is " DEFAULT_FILENAME ".
", name);
}

struct option longopts[] = {
	{ "set", 2, NULL, 's' },
	{ "list", 0, NULL, 'l' },
	{ "help", 0, NULL, 'h' },
	{ "version", 0, NULL, 'V' },
	{ NULL, 0, 0, 0 }
};

int main(int argc, char **argv)
{
	int ch;
	
	while ((ch = getopt_long(argc, argv, "s::lhV", longopts, NULL)) != -1) {
		switch (ch) {
			case 's':
				if (!optarg && optind < argc && argv[optind][0] != '-')
					optarg = argv[optind];
				return !set_rules((optarg) ? optarg : DEFAULT_FILENAME);
			case 'l':
				return !list_rules();
			case 'h':
				usage(argv[0]);
				return 1;
			case 'V':
				printf("bpset " VERSION "\n");
				return 1;
			default:
				return 1;
		}
	}
	
	fprintf(stderr, "%s: no parameters specified\n", argv[0]);
	return 1;
}

