#ifndef __BINDPRIVS_H
#define __BINDPRIVS_H

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