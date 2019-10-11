/*
 *  libauthbind.c - bind(2)-redirector library for authbind
 *
 *  authbind is Copyright (C) 1998 Ian Jackson
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. 
 * 
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

#define STDERRSTR_CONST(m) write(2,m,sizeof(m)-1)
#define STDERRSTR_STRING(m) write(2,m,strlen(m))

typedef void anyfn_type(void);

static anyfn_type *find_any(const char *name) {
  static const char *dlerr;
  anyfn_type *kv;

  kv= dlsym(RTLD_NEXT,name); if (kv) return kv;
  dlerr= dlerror(); if (!dlerr) dlerr= "dlsym() failed for no reason";
  STDERRSTR_CONST("libauthbind: error finding original version of ");
  STDERRSTR_STRING(name);
  STDERRSTR_CONST(": ");
  STDERRSTR_STRING(dlerr);
  STDERRSTR_STRING("\n");
  errno= ENOSYS;
  return 0;
}

#define socket_args int domain, int type, int protocol
#define bind_args   int fd, const struct sockaddr *addr, socklen_t addrlen
#define WRAPS(X)				\
    X(socket, (domain,type,protocol))		\
    X(bind,   (fd,addr,addrlen))

#define DEF_OLD(fn,args)				\
  typedef int fn##_fn_type(fn##_args);			\
  static int find_##fn(fn##_args);			\
  static fn##_fn_type find_##fn, *old_##fn=find_##fn;	\
  static int find_##fn(fn##_args) {			\
    anyfn_type *anyfn;					\
    anyfn= find_any(#fn); if (!anyfn) return -1;	\
    old_##fn= (fn##_fn_type*)anyfn;			\
    return old_##fn args;				\
  }

WRAPS(DEF_OLD)

#define WRAP(fn) int fn(fn##_args)

typedef struct{
    int af;
    union {
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
    } bound;
} fdinfo;
static fdinfo **table;
static int tablesz;

static fdinfo *lookup(int fd) {
    if (fd>=tablesz) return 0;
    return table[fd];
}

static int chkaddr(fdinfo *ent,
		   const struct sockaddr *addr, socklen_t addrlen) {
    if (addr->sa_family!=ent->af) { errno=EAFNOSUPPORT; return -1; }
    socklen_t expectlen;
    switch (addr->sa_family) {
    case AF_INET:  expectlen=sizeof(ent->bound.v4); break;
    case AF_INET6: expectlen=sizeof(ent->bound.v6); break;
    default: abort();
    }
    if (addrlen!=expectlen) { errno=EINVAL; return -1; }
    return 0;
}

WRAP(socket) {
    if (!((domain==AF_INET || domain==AF_INET6) &&
	  type==SOCK_DGRAM))
	return old_socket(domain,type,protocol);
    int fd=socket(AF_UNIX,SOCK_DGRAM,0);
    if (fd<0) return fd;
    if (fd>=tablesz) {
	int newsz=(fd+1)*2;
	table=realloc(table,newsz*sizeof(*table));
	if (!table) goto fail;
	while (tablesz<newsz) table[tablesz++]=0;
    }
    free(table[fd]);
    table[fd]=malloc(sizeof(*table[fd]));
    if (!table[fd]) goto fail;
    table[fd]->af=domain;
    table[fd]->bound.v4.sin_family=0;
    return fd;

 fail:
    close(fd);
    return -1;
}

WRAP(bind) {
    fdinfo *ent=lookup(fd);
    if (!ent) return bind(fd,addr,addrlen);
    if (chkaddr(ent,addr,addrlen)) return -1;
    memset(&ent->bound,0,sizeof(ent->bound));
    memcpy(&ent->bound,addr,addrlen);
    return 0;
}
