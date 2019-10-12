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
#define WRAPS(X) X(socket, (domain,type,protocol))

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

WRAP(socket) {
    return old_socket(domain,type,protocol);
}

#if 0
WRAP(bind, (int fd, const struct sockaddr *addr, socklen_t addrlen), {
    
});
		    
static bindfn_type find_bind, *old_bind= find_bind;

int find_bind(int fd, const struct sockaddr *addr, socklen_t addrlen) {
  anyfn_type *anyfn;
  anyfn= find_any("bind"); if (!anyfn) return -1;
  old_bind= (bindfn_type*)anyfn;
  return old_bind(fd,addr,addrlen);
}

static int exiterrno(int e) {
  _exit(e>0 && e<128 ? e : -1);
}

static void removepreload(void) {
  const char *myself, *found;
  char *newval, *preload;
  int lpreload, lmyself, before, after;

  preload= getenv(PRELOAD_VAR);
  myself= getenv(AUTHBINDLIB_VAR);
  if (!myself || !preload) return;

  lpreload= strlen(preload);
  lmyself= strlen(myself);

  if (lmyself < 1 || lpreload<lmyself) return;
  if (lpreload==lmyself) {
    if (!strcmp(preload,myself)) unsetenv(PRELOAD_VAR);
    return;
  }
  if (!memcmp(preload,myself,lmyself) && preload[lmyself]==':') {
    before= 0; after= lpreload-(lmyself+1);
  } else if (!memcmp(preload+lpreload-lmyself,myself,lmyself) &&
	     preload[lpreload-(lmyself+1)]==':') {
    before= lpreload-(lmyself+1); after= 0;
  } else {
    if (lpreload<lmyself+2) return;
    found= preload+1;
    for (;;) {
      found= strstr(found,myself); if (!found) return;
      if (found > preload+lpreload-(lmyself+1)) return;
      if (found[-1]==':' && found[lmyself]==':') break;
      found++;
    }
    before= found-preload;
    after= lpreload-(before+lmyself+1);
  }
  newval= malloc(before+after+1);
  if (newval) {
    memcpy(newval,preload,before);
    strcpy(newval+before,preload+lpreload-after);
    if (setenv(PRELOAD_VAR,newval,1)) return;
    free(newval);
  }
  strcpy(preload+before,preload+lpreload-after);
  return;
}

int _init(void);
int _init(void) {
  char *levels;
  int levelno;

  /* If AUTHBIND_LEVELS is
   *  unset => always strip from preload
   *  set and starts with `y' => never strip from preload, keep AUTHBIND_LEVELS
   *  set to integer > 1 => do not strip now, subtract one from AUTHBIND_LEVELS
   *  set to integer 1 => do not strip now, unset AUTHBIND_LEVELS
   *  set to empty string or 0 => strip now, unset AUTHBIND_LEVELS
   */
  levels= getenv(AUTHBIND_LEVELS_VAR);
  if (levels) {
    if (levels[0]=='y') return 0;
    levelno= atoi(levels);
    if (levelno > 0) {
      levelno--;
      if (levelno > 0) sprintf(levels,"%d",levelno);
      else unsetenv(AUTHBIND_LEVELS_VAR);
      return 0;
    }
    unsetenv(AUTHBIND_LEVELS_VAR);
  }
  removepreload();
  return 0;
}

static const int evilsignals[]= { SIGFPE, SIGILL, SIGSEGV, SIGBUS, 0 };

int bind(int fd, const struct sockaddr *addr, socklen_t addrlen) {
  pid_t child, rchild;
  char portarg[5], addrarg[33];
  const char *afarg;
  int i, r, status, restore_sigchild;
  const int *evilsignal;
  sigset_t block, saved;
  struct sigaction old_sigchild;
  unsigned int portval;

  switch (addr->sa_family) {
  case AF_INET:
    portval = ((struct sockaddr_in*)addr)->sin_port;
    if (addrlen != sizeof(struct sockaddr_in)) goto bail;
    break;
  case AF_INET6:
    portval = ((struct sockaddr_in6*)addr)->sin6_port;
    if (addrlen != sizeof(struct sockaddr_in6)) goto bail;
    break;
  default:
    goto bail;
  }

  if (!geteuid() || portval == 0 || ntohs(portval) >= IPPORT_RESERVED) {
  bail:
    return old_bind(fd,addr,addrlen);
  }

  sigfillset(&block);
  for (evilsignal=evilsignals;
       *evilsignal;
       evilsignal++)
    sigdelset(&block,*evilsignal);
  if (sigprocmask(SIG_BLOCK,&block,&saved)) return -1;

  switch (addr->sa_family) {
  case AF_INET:
    afarg = 0;
    sprintf(addrarg,"%08lx",
	    ((unsigned long)(((struct sockaddr_in*)addr)->sin_addr.s_addr))
	    &0x0ffffffffUL);
    break;
  case AF_INET6:
    afarg = "6";
    for (i=0; i<16; i++)
      sprintf(addrarg+i*2,"%02x",
	      ((struct sockaddr_in6*)addr)->sin6_addr.s6_addr[i]);
    break;
  default:
    abort();
  }
  sprintf(portarg,"%04x",
	  portval&0x0ffff);

  restore_sigchild= 0;
  if (sigaction(SIGCHLD,NULL,&old_sigchild)) return -1;
  if (old_sigchild.sa_handler == SIG_IGN) {
    struct sigaction new_sigchild;

    new_sigchild.sa_handler= SIG_DFL;
    sigemptyset(&new_sigchild.sa_mask);
    new_sigchild.sa_flags= 0;
    if (sigaction(SIGCHLD,&new_sigchild,&old_sigchild)) return -1;
    restore_sigchild= 1;
  }

  child= fork(); if (child==-1) goto x_err;

  if (!child) {
    if (dup2(fd,0)) exiterrno(errno);
    removepreload();
    execl(HELPER,HELPER,addrarg,portarg,afarg,(char*)0);
    status= errno > 0 && errno < 127 ? errno : 127;
    STDERRSTR_CONST("libauthbind: possible installation problem - "
		    "could not invoke " HELPER "\n");
    exiterrno(status);
  }

  rchild= waitpid(child,&status,0);
  if (rchild==-1) goto x_err;
  if (rchild!=child) { errno= ECHILD; goto x_err; }

  if (WIFEXITED(status)) {
    if (WEXITSTATUS(status)) {
      errno= WEXITSTATUS(status);
      if (errno >= 127) errno= ENXIO;
      goto x_err;
    }
    r= 0;
    goto x;
  } else {
    errno= ENOSYS;
    goto x_err;
  }

x_err:
  r= -1;
x:
  if (sigprocmask(SIG_SETMASK,&saved,0)) abort();
  if (restore_sigchild) {
    if (sigaction(SIGCHLD,&old_sigchild,NULL)) return -1;
    if (old_sigchild.sa_handler == SIG_IGN) {
      int discard;
      while (waitpid(-1, &discard, WNOHANG) > 0)
	;
    }
  }
  return r;
}
#endif
