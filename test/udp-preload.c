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

#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

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
#define setsockopt_args  int fd, int level, int optname, \
                         const void *optval, socklen_t optlen
#define WRAPS(X)					\
    X(socket,     (domain,type,protocol))		\
    X(bind,       (fd,addr,addrlen))			\
    X(setsockopt, (fd,level,optname,optval,optlen))

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
} fdinfo;
static fdinfo **table;
static int tablesz;

static fdinfo *lookup(int fd) {
    if (fd>=tablesz) return 0;
    return table[fd];
}

#define ADDRPORTSTRLEN (INET6_ADDRSTRLEN+1+5) /* not including nul */

static int addrport2str(char buf[ADDRPORTSTRLEN+1],
			const struct sockaddr *addr, socklen_t addrlen) {
    const void *addrv=addr;
    const void *iav;
    const struct sockaddr_in  *sin;
    const struct sockaddr_in6 *sin6;
    uint16_t port;
    socklen_t el;
    switch (addr->sa_family) {
    case AF_INET:  sin =addrv; el=sizeof(*sin ); iav=&sin ->sin_addr ; port=sin ->sin_port ; break;
    case AF_INET6: sin6=addrv; el=sizeof(*sin6); iav=&sin6->sin6_addr; port=sin6->sin6_port; break;
    default: errno=ESRCH; return -1;
    }
//fprintf(stderr,"af=%lu el=%lu addrlen=%lu\n",
//	(unsigned long)addr->sa_family,
//	(unsigned long)el,
//	(unsigned long)addrlen);
    if (addrlen!=el) { errno=EINVAL; return -1; }
    char *p=buf;
    if (!inet_ntop(addr->sa_family,iav,p,INET6_ADDRSTRLEN)) return -1;
    p+=strlen(p);
    sprintf(p,",%u",(unsigned)ntohs(port));
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
    return fd;

 fail:
    close(fd);
    return -1;
}

WRAP(bind) {
    fdinfo *ent=lookup(fd);
    if (!ent) return old_bind(fd,addr,addrlen);
    const char *dir = getenv("UDP_PRELOAD_DIR");
    if (!dir) { errno=ECHILD; return -1; }
    struct sockaddr_un sun;
    memset(&sun,0,sizeof(sun));
    sun.sun_family=AF_UNIX;
    int dl = strlen(dir);
    if (dl + 1 + ADDRPORTSTRLEN + 1 > sizeof(sun.sun_path)) {
	errno=ENAMETOOLONG; return -1;
    }
    strcpy(sun.sun_path,dir);
    char *p=sun.sun_path+dl;
    *p++='/';
    if (addrport2str(p,addr,addrlen)) return -1;
//fprintf(stderr,"binding %s\n",sun.sun_path);
    if (unlink(sun.sun_path) && errno!=ENOENT) return -1;
    return old_bind(fd,(const void*)&sun,sizeof(sun));
}

WRAP(setsockopt) {
    fdinfo *ent=lookup(fd);
    if (!ent) return old_setsockopt(fd,level,optname,optval,optlen);
    if (ent->af==AF_INET6 && level==IPPROTO_IPV6 && optname==IPV6_V6ONLY
	&& optlen==sizeof(int) && *(int*)optval==1) {
	return 0;
    }
    errno=ENOTTY;
    return -1;
}
