/* polypath
 * send/receive module for secnet
 * for multi-route setups */
/*
 * This file is part of secnet.
 * See README for full list of copyright holders.
 *
 * secnet is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version d of the License, or
 * (at your option) any later version.
 * 
 * secnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * version 3 along with secnet; if not, see
 * https://www.gnu.org/licenses/gpl.html.
 */

#include "secnet.h"
#include "util.h"
#include "unaligned.h"
#include "comm-common.h"

#include <adns.h>
#include <ctype.h>

#ifdef CONFIG_IPV6

static comm_sendmsg_fn polypath_sendmsg;

struct interf {
    char *name; /* from malloc */
    struct udpsocks socks;
    bool_t experienced_xmit_noaf[MAX_AF+1];
    LIST_ENTRY(interf) entry;
};

struct polypath {
    struct udpcommon uc;
    int max_interfs;
    const char *const *ifname_pats;
    const char *const *monitor_command;
    bool_t permit_loopback;
    LIST_HEAD(interf_list, interf) interfs;
    struct buffer_if lbuf;
    int monitor_fd;
    pid_t monitor_pid;
    int privsep_incoming_fd;
    int privsep_ipcsock_fd;
};

static void polypath_phase_shutdown(void *sst, uint32_t newphase);

#define LG 0, st->uc.cc.cl.description, &st->uc.cc.loc

static const char *const default_loopback_ifname_pats[] = {
    "!lo", 0
};
static const char *const default_ifname_pats[] = {
    "!tun*","!tap*","!sl*","!userv*", "*", 0
};

static const char *const default_monitor_command[] = {
#if __linux__
    DATAROOTDIR "/secnet/" "polypath-interface-monitor-linux", 0
#else
    0
#endif
};

static const char *polypath_addr_to_string(void *commst,
					   const struct comm_addr *ca)
{
    static char sbuf[100];

    snprintf(sbuf, sizeof(sbuf), "polypath:%s",
	     iaddr_to_string(&ca->ia));
    return sbuf;
}

static bool_t ifname_search_pats(struct polypath *st, struct cloc loc,
				 const char *ifname, char *want_io,
				 const char *const *pats) {
    /* Returns True iff we found a list entry, in which case *want_io
     * is set to the sense of that entry.  Otherwise *want_io is set
     * to the sense of the last entry, or unchanged if there were no pats. */
    if (!pats)
	return False;
    const char *const *pati;
    for (pati=pats; *pati; pati++) {
	const char *pat=*pati;
	if (*pat=='!' || *pat=='+') { *want_io=*pat; pat++; }
	else if (*pat=='*' || isalnum((unsigned char)*pat)) { *want_io='+'; }
	else cfgfatal(loc,"polypath","invalid interface name pattern `%s'",pat);
	int match=fnmatch(pat,ifname,0);
	if (match==0) return True;
	if (match!=FNM_NOMATCH)
	    cfgfatal(loc,"polypath","fnmatch failed! (pattern `%s')",pat);
    }
    return False;
}

static char ifname_wanted(struct polypath *st, struct cloc loc,
			  const char *ifname) {
    char want='!'; /* pretend an empty cfg ends with !<doesn'tmatch> */
    if (ifname_search_pats(st,loc,ifname,&want, st->ifname_pats))
	return want;
    if (want!='!') /* last pattern was positive, do not search default */
	return '!';
    if (!st->permit_loopback &&
	ifname_search_pats(st,loc,ifname,&want, default_loopback_ifname_pats))
	return want;
    if (ifname_search_pats(st,loc,ifname,&want, default_ifname_pats))
	return want;
    abort();
}

static int polypath_beforepoll(void *state, struct pollfd *fds, int *nfds_io,
			       int *timeout_io)
{
    struct polypath *st=state;
    BEFOREPOLL_WANT_FDS(1);
    fds[0].fd=st->monitor_fd;
    fds[0].events=POLLIN;
    return 0;
}

static inline bool_t matches32(uint32_t word, uint32_t prefix, int prefixlen)
{
    assert(prefixlen>0);
    assert(prefixlen<=32);
    uint32_t mask = ~(((uint32_t)1 << (32-prefixlen)) - 1);
    assert(!(prefix & ~mask));
    return (word & mask) == prefix;
}

/* These macros expect
 *    bad_fn_type *const bad;
 *    void *badctx;
 * and
 *   out:
 */
#define BAD(m)     do{ bad(st,badctx,M_WARNING,m,0);  goto out; }while(0)
#define BADE(m,ev) do{ bad(st,badctx,M_WARNING,m,ev); goto out; }while(0)
typedef void bad_fn_type(struct polypath *st, void *badctx,
			 int mclass, const char* m, int ev);

typedef void polypath_ppml_callback_type(struct polypath *st,
          bad_fn_type *bad, void *badctx,
          bool_t add, char want,
          const char *ifname, const char *ifaddr,
          const union iaddr *ia, int fd /* -1 if none yet */);

struct ppml_bad_ctx {
    const char *orgl;
    char *undospace;
};

static void ppml_bad(struct polypath *st, void *badctx,
		     int mclass, const char *m, int ev)
{
    struct ppml_bad_ctx *bc=badctx;
    if (bc->undospace)
	*(bc->undospace)=' ';
    lg_perror(LG,mclass,ev,
	      "error processing polypath state change: %s"
	      " (while processing `%s')",
	      m,bc->orgl);
}

static void polypath_process_monitor_line(struct polypath *st, char *orgl,
                                      polypath_ppml_callback_type *callback)
    /* always calls callback with fd==-1 */
{
    struct udpcommon *uc=&st->uc;
    char *l=orgl;
    bad_fn_type (*const bad)=ppml_bad;
    struct ppml_bad_ctx badctx[1]={{
	    .orgl=orgl,
	    .undospace=0
	}};

    bool_t add;
    int c=*l++;
    if (c=='+') add=True;
    else if (c=='-') add=False;
    else BAD("bad +/-");

    int proto;
    c=*l++;
    if (c=='4') proto=AF_INET;
    else if (c=='6') proto=AF_INET6;
    else BAD("bad proto");

    char *space=strchr(l,' ');
    if (!space) BAD("no first space");
    const char *ifname=space+1;

    space=strchr(ifname,' ');
    if (!space) BAD("no second space");
    const char *ifaddr=space+1;
    *space=0;
    badctx->undospace=space;

    union iaddr ia;
    FILLZERO(ia);
    socklen_t salen=sizeof(ia);
    int r=adns_text2addr(ifaddr,uc->port, adns_qf_addrlit_ipv4_quadonly,
			 &ia.sa, &salen);
    assert(r!=ENOSPC);
    if (r) BADE("adns_text2addr",r);
    if (ia.sa.sa_family!=proto) BAD("address family mismatch");

#define DONT(m) do{							\
	if (add)							\
	    lg_perror(LG,M_INFO,0,"ignoring %s [%s]: %s",ifname,ifaddr,m); \
	goto out;							\
    }while(0)

    char want=ifname_wanted(st,st->uc.cc.loc,ifname);
    if (want=='!') DONT("unwanted interface name");

    switch (ia.sa.sa_family) {
    case AF_INET6: {
	const struct in6_addr *i6=&ia.sin6.sin6_addr;
#define DONTKIND(X,m) \
	if (IN6_IS_ADDR_##X(i6)) DONT("IPv6 address is " m)
	DONTKIND(UNSPECIFIED, "unspecified");
	DONTKIND(MULTICAST  , "multicast"  );
	DONTKIND(LINKLOCAL  , "link local" );
	DONTKIND(SITELOCAL  , "site local" );
	DONTKIND(V4MAPPED   , "v4-mapped"  );
	if (!st->permit_loopback)
	    DONTKIND(LOOPBACK   , "loopback"   );
#undef DONTKIND
#define DONTMASK(w7x,w6x,prefixlen,m)					\
	if (matches32(get_uint32(i6->s6_addr),				\
                      ((uint32_t)0x##w7x << 16) | (uint32_t)0x##w6x,	\
                      prefixlen))					\
	    DONT("IPv6 address is " m)
        DONTMASK( 100,   0,  8, "Discard-Only (RFC6666)");
	DONTMASK(2001,   0, 23, "in IETF protocol block (RFC2928)");
	DONTMASK(fc00,   0,  7, "Uniqe Local unicast (RFC4193)");
#undef DONTMASK
	break;
    }
    case AF_INET: {
	const uint32_t i4=htonl(ia.sin.sin_addr.s_addr);
	if (i4==INADDR_ANY) DONT("IPv4 address is any/unspecified");
	if (i4==INADDR_BROADCAST) DONT("IPv4 address is all hosts broadcast");
#define DONTMASK(b3,b2,b1,b0,prefixlen,m) do{				\
	    const uint8_t prefixbytes[4] = { (b3),(b2),(b1),(b0) };	\
	    if (matches32(i4,get_uint32(prefixbytes),prefixlen))	\
		DONT("IPv4 address is " m);				\
	}while(0)
	DONTMASK(169,254,0,0, 16, "link local");
	DONTMASK(224,  0,0,0,  4, "multicast");
	DONTMASK(192,  0,0,0, 24, "in IETF protocol block (RFC6890)");
	DONTMASK(240,  0,0,0,  4, "in reserved addressing block (RFC1112)");
	if (!st->permit_loopback)
	    DONTMASK(127,  0,0,0,  8, "loopback");
#undef DONTMASK
	break;
    }
    default:
	abort();
    }

#undef DONT

    /* OK, process it */
    callback(st, bad,badctx, add,want, ifname,ifaddr,&ia,-1);

 out:;
}

static void dump_pria(struct polypath *st, struct interf_list *interfs,
		      const char *ifname, char want)
{
#ifdef POLYPATH_DEBUG
    struct interf *interf;
    if (ifname)
	lg_perror(LG,M_DEBUG,0, "polypath record ifaddr `%s' (%c)",
		  ifname, want);
    LIST_FOREACH(interf, interfs, entry) {
	lg_perror(LG,M_DEBUG,0, "  polypath interface `%s', nsocks=%d",
		  interf->name, interf->socks.n_socks);
	int i;
	for (i=0; i<interf->socks.n_socks; i++) {
	    struct udpsock *us=&interf->socks.socks[i];
	    lg_perror(LG,M_DEBUG,0, "    polypath sock fd=%d addr=%s",
		      us->fd, iaddr_to_string(&us->addr));
	}
    }
#endif
}

static bool_t polypath_make_socket(struct polypath *st,
				   bad_fn_type *bad, void *badctx,
				   struct udpsock *us, const char *ifname)
    /* on error exit has called bad; might leave us->fd as -1 */
{
    assert(us->fd==-1);

    bool_t ok=udp_make_socket(&st->uc,us,M_WARNING);
    if (!ok) BAD("unable to set up socket");
    int r=setsockopt(us->fd,SOL_SOCKET,SO_BINDTODEVICE,
		     ifname,strlen(ifname)+1);
    if (r) BADE("setsockopt(,,SO_BINDTODEVICE,)",errno);
    return True;

 out:
    return False;
}

static void polypath_record_ifaddr(struct polypath *st,
				   bad_fn_type *bad, void *badctx,
				   bool_t add, char want,
				   const char *ifname,
				   const char *ifaddr,
				   const union iaddr *ia, int fd)
{
    struct udpcommon *uc=&st->uc;
    struct interf *interf=0;
    int max_interfs;
    struct udpsock *us=0;

    struct interf_list *interfs;
    switch (want) {
    case '+':  interfs=&st->interfs;            max_interfs=st->max_interfs;
    default:   fatal("polypath: got bad want (%#x, %s)", want, ifname);
    }

    dump_pria(st,interfs,ifname,want);

    int n_ifs=0;
    LIST_FOREACH(interf,interfs,entry) {
	if (!strcmp(interf->name,ifname))
	    goto found_interf;
	n_ifs++;
    }
    /* not found */
    if (n_ifs==max_interfs) BAD("too many interfaces");
    interf=malloc(sizeof(*interf));
    if (!interf) BADE("malloc for new interface",errno);
    interf->name=0;
    interf->socks.n_socks=0;
    FILLZERO(interf->experienced_xmit_noaf);
    LIST_INSERT_HEAD(interfs,interf,entry);
    interf->name=strdup(ifname);
    udp_socks_register(&st->uc,&interf->socks,interf->name);
    if (!interf->name) BADE("strdup interface name",errno);
 found_interf:

    if (add) {
	if (interf->socks.n_socks == UDP_MAX_SOCKETS)
	    BAD("too many addresses on this interface");
	struct udpsock *us=&interf->socks.socks[interf->socks.n_socks];
	us->fd=-1;
	COPY_OBJ(us->addr,*ia);
	if (fd<0) {
	    bool_t ok=polypath_make_socket(st,bad,badctx, us,ifname);
	    if (!ok) goto out;
	} else {
	    bool_t ok=udp_import_socket(uc,us,M_WARNING,fd);
	    if (!ok) goto out;
	    fd=-1;
	}
	interf->socks.n_socks++;
	lg_perror(LG,M_INFO,0,"using %s %s",ifname,
		  iaddr_to_string(&us->addr));
	us=0; /* do not destroy this socket during `out' */
    } else {
	int i;
	for (i=0; i<interf->socks.n_socks; i++)
	    if (iaddr_equal(&interf->socks.socks[i].addr,ia,True))
		goto address_remove_found;
	bad(st,badctx,M_DEBUG,"address to remove not found",0);
	goto out;
    address_remove_found:
	lg_perror(LG,M_INFO,0,"removed %s %s",ifname,
		  iaddr_to_string(&interf->socks.socks[i].addr));
	udp_destroy_socket(&st->uc,&interf->socks.socks[i]);
	interf->socks.socks[i]=
	    interf->socks.socks[--interf->socks.n_socks];
    }

 out:
    if (us)
	udp_destroy_socket(uc,us);
    if (fd>=0)
	close(fd);
    if (interf && !interf->socks.n_socks) {
	udp_socks_deregister(&st->uc,&interf->socks);
	LIST_REMOVE(interf,entry);
	free(interf->name);
	free(interf);
    }

    dump_pria(st,interfs,0,0);
}

static void subproc_problem(struct polypath *st,
			    enum async_linebuf_result alr, const char *emsg)
{
    int status;
    assert(st->monitor_pid);

    pid_t gotpid=waitpid(st->monitor_pid,&status,WNOHANG);
    if (gotpid==st->monitor_pid) {
	st->monitor_pid=0;
	lg_exitstatus(LG,M_FATAL,status,"interface monitor");
    } else if (gotpid<0)
	lg_perror(LG,M_ERR,errno,"unable to reap interface monitor");
    else
	assert(gotpid==0);

    if (alr==async_linebuf_eof)
	lg_perror(LG,M_FATAL,0,"unexpected EOF from interface monitor");
    else
	lg_perror(LG,M_FATAL,0,"bad output from interface monitor: %s",emsg);
    assert(!"not reached");
}

/* Used in non-privsep case, and in privsep child */
static void afterpoll_monitor(struct polypath *st, struct pollfd *fd,
			      polypath_ppml_callback_type *callback)
{
    enum async_linebuf_result alr;
    const char *emsg;
    
    while ((alr=async_linebuf_read(fd,&st->lbuf,&emsg)) == async_linebuf_ok)
	polypath_process_monitor_line(st,st->lbuf.base,callback);

    if (alr==async_linebuf_nothing)
	return;

    subproc_problem(st,alr,emsg);
}

/* Used in non-privsep case only - glue for secnet main loop */
static void polypath_afterpoll_monitor(void *state, struct pollfd *fds,
				       int nfds)
{
    struct polypath *st=state;
    if (nfds<1) return;
    afterpoll_monitor(st,fds,polypath_record_ifaddr);
}

/* Actual udp packet sending work */
static bool_t polypath_sendmsg(void *commst, struct buffer_if *buf,
			  const struct comm_addr *dest,
			  struct comm_clientinfo *clientinfo)
{
    struct polypath *st=commst;
    struct interf *interf;
    bool_t allreasonable=True;
    int af=dest->ia.sa.sa_family;

    LIST_FOREACH(interf,&st->interfs,entry) {
	int i;
	bool_t attempted=False, reasonable=False;
	for (i=0; i<interf->socks.n_socks; i++) {
	    struct udpsock *us=&interf->socks.socks[i];
	    if (af != us->addr.sa.sa_family)
		continue;
	    attempted=True;
	    int r=sendto(us->fd,buf->start,buf->size,
			 0,&dest->ia.sa,iaddr_socklen(&dest->ia));
	    udp_sock_experienced(0,&st->uc,&interf->socks,us,
				 &dest->ia,af, r,errno);
	    if (r>=0) {
		reasonable=True;
		break;
	    }
	    if (!(errno==EAFNOSUPPORT || errno==ENETUNREACH))
		reasonable=True;
	    lg_perror(LG,M_DEBUG,errno,"%s [%s] xmit %"PRIu32" bytes to %s",
		      interf->name,iaddr_to_string(&us->addr),
		      buf->size,iaddr_to_string(&dest->ia));
	}
	if (!attempted)
	    if (!interf->experienced_xmit_noaf[af]++)
		lg_perror(LG,M_WARNING,0,
			  "%s has no suitable address to transmit %s",
			  interf->name, af_name(af));
	allreasonable *= reasonable;
    }
    return allreasonable;
}

/* Non-privsep: called in (sole) child.  Privsep: in grandchild. */
static void child_monitor(struct polypath *st, int childfd)
{
    dup2(childfd,1);
    execvp(st->monitor_command[0],(char**)st->monitor_command);
    fprintf(stderr,"secnet: cannot execute %s: %s\n",
	    st->monitor_command[0], strerror(errno));
    exit(-1);
}

/* General utility function. */
static void start_subproc(struct polypath *st, void (*make_fdpair)(int[2]),
			  void (*child)(struct polypath *st, int childfd),
			  const char *desc)
{
    int pfds[2];

    assert(!st->monitor_pid);
    assert(st->monitor_fd<0);

    make_fdpair(pfds);

    pid_t pid=fork();
    if (!pid) {
	afterfork();
	close(pfds[0]);
	child(st,pfds[1]);
	abort();
    }
    if (pid<0)
	fatal_perror("%s: failed to fork for interface monitoring",
		     st->uc.cc.cl.description);

    close(pfds[1]);
    st->monitor_pid=pid;
    st->monitor_fd=pfds[0];
    setnonblock(st->monitor_fd);

    lg_perror(LG,M_NOTICE,0, "%s: spawning %s [pid %ld]",
	      st->uc.cc.cl.description, desc, (long)st->monitor_pid);
}

/* Non-privsep only: glue for forking the monitor, from the main loop */
static void polypath_phase_startmonitor(void *sst, uint32_t newphase)
{
    struct polypath *st=sst;
    start_subproc(st,pipe_cloexec,child_monitor,
		  "interface monitor (no privsep)");
    register_for_poll(st,polypath_beforepoll,
		      polypath_afterpoll_monitor,"polypath");
}

/*----- Privsep-only: -----*/

/*
 * We use two subprocesses, a child and a grandchild.  These are
 * forked before secnet drops privilege.
 *
 * The grandchild is the same interface monitor helper script as used
 * in the non-privsep case.  But its lines are read by the child
 * instead of by the main secnet.  The child is responsible for
 * creating the actual socket (binding it, etc.).  Each socket is
 * passed to secnet proper via fd passing, along with a data message
 * describing the interface name and address.  The child does not
 * retain a list of current interfaces and addresses - it trusts the
 * interface monitor to get that right.  secnet proper still maintains
 * that data structure.
 *
 * The result is that much of the non-privsep code can be reused, but
 * just plumbed together differently.
 *
 * The child does not retain the socket after passing it on.
 * Interface removals are handled similarly but without any fd.
 *
 * The result is that the configuration's limits on which interfaces
 * and ports secnet may use are enforced by the privileged child.
 */

struct privsep_mdata {
    bool_t add;
    char ifname[100];
    union iaddr ia;
    char want; /* `+', for now */
};

static void papp_bad(struct polypath *st, void *badctx,
		     int mclass, const char *m, int ev)
{
    const struct privsep_mdata *mdata=(const void*)st->lbuf.start;
    const char *addr_str=badctx;

    lg_perror(LG,mclass,ev,
	      "error processing polypath address change %s %s [%s]: %s",
	      mdata->add ? "+" : "-",
	      mdata->ifname, addr_str, m);
}

static void polypath_afterpoll_privsep(void *state, struct pollfd *fds,
				       int nfds)
/* In secnet proper; receives messages from child. */
{
    struct polypath *st=state;

    if (nfds<1) return;

    int revents=fds[0].revents;

    const char *badbit=pollbadbit(revents);
    if (badbit) subproc_problem(st,async_linebuf_broken,badbit);

    if (!(revents & POLLIN)) return;

    for (;;) {
	if (st->lbuf.size==sizeof(struct privsep_mdata)) {
	    const struct privsep_mdata *mdata=(const void*)st->lbuf.start;
	    if (mdata->add && st->privsep_incoming_fd<0)
		fatal("polypath (privsep): got add message data but no fd");
	    if (!mdata->add && st->privsep_incoming_fd>=0)
		fatal("polypath (privsep): got remove message data with fd");
	    if (!memchr(mdata->ifname,0,sizeof(mdata->ifname)))
		fatal("polypath (privsep): got ifname with no terminating nul");
	    int af=mdata->ia.sa.sa_family;
	    if (!(af==AF_INET6 || af==AF_INET))
		fatal("polypath (privsep): got message data but bad AF %d",af);
	    const char *addr_str=iaddr_to_string(&mdata->ia);
	    polypath_record_ifaddr(st,papp_bad,(void*)addr_str,
				   mdata->add,mdata->want,
				   mdata->ifname,addr_str,
				   &mdata->ia, st->privsep_incoming_fd);
	    st->privsep_incoming_fd=-1;
	    st->lbuf.size=0;
	}
	struct msghdr msg;
	int fd;
	size_t cmsgdatalen=sizeof(fd);
	char cmsg_control_buf[CMSG_SPACE(cmsgdatalen)];
	struct iovec iov;

	FILLZERO(msg);
	msg.msg_iov=&iov;
	msg.msg_iovlen=1;

	iov.iov_base=st->lbuf.start+st->lbuf.size;
	iov.iov_len=sizeof(struct privsep_mdata)-st->lbuf.size;

	if (st->privsep_incoming_fd<0) {
	    msg.msg_control=cmsg_control_buf;
	    msg.msg_controllen=sizeof(cmsg_control_buf);
	}

	ssize_t got=recvmsg(st->monitor_fd,&msg,0);
	if (got<0) {
	    if (errno==EINTR) continue;
	    if (iswouldblock(errno)) break;
	    fatal_perror("polypath (privsep): recvmsg failed");
	}
	if (got==0)
	    subproc_problem(st,async_linebuf_eof,0);

	st->lbuf.size+=got;

	if (msg.msg_controllen) {
	    size_t cmsgdatalen=sizeof(st->privsep_incoming_fd);
	    struct cmsghdr *h=CMSG_FIRSTHDR(&msg);
	    if (!(st->privsep_incoming_fd==-1 &&
		  h &&
		  h->cmsg_level==SOL_SOCKET &&
		  h->cmsg_type==SCM_RIGHTS &&
		  h->cmsg_len==CMSG_LEN(cmsgdatalen) &&
		  !CMSG_NXTHDR(&msg,h)))
		subproc_problem(st,async_linebuf_broken,"bad cmsg");
	    memcpy(&st->privsep_incoming_fd,CMSG_DATA(h),cmsgdatalen);
	    assert(st->privsep_incoming_fd>=0);
	}

    }
}

static void privsep_handle_ifaddr(struct polypath *st,
				   bad_fn_type *bad, void *badctx,
				   bool_t add, char want,
				   const char *ifname,
				   const char *ifaddr,
				   const union iaddr *ia, int fd_dummy)
/* In child: handles discovered wanted interfaces, making sockets
   and sending them to secnet proper. */
{
    struct msghdr msg;
    struct iovec iov;
    struct udpsock us={ .fd=-1 };
    size_t cmsgdatalen=sizeof(us.fd);
    char cmsg_control_buf[CMSG_SPACE(cmsgdatalen)];

    assert(fd_dummy==-1);

    struct privsep_mdata mdata;
    FILLZERO(mdata);
    mdata.add=add;

    size_t l=strlen(ifname);
    if (l>=sizeof(mdata.ifname)) BAD("interface name too long");
    strcpy(mdata.ifname,ifname);
    mdata.want=want;

    COPY_OBJ(mdata.ia,*ia);

    iov.iov_base=&mdata;
    iov.iov_len =sizeof(mdata);

    FILLZERO(msg);
    msg.msg_iov=&iov;
    msg.msg_iovlen=1;

    if (add) {
	COPY_OBJ(us.addr,*ia);
	bool_t ok=polypath_make_socket(st,bad,badctx,&us,ifname);
	if (!ok) goto out;

	msg.msg_control=cmsg_control_buf;
	msg.msg_controllen=sizeof(cmsg_control_buf);

	struct cmsghdr *h=CMSG_FIRSTHDR(&msg);
	h->cmsg_level=SOL_SOCKET;
	h->cmsg_type =SCM_RIGHTS;
	h->cmsg_len  =CMSG_LEN(cmsgdatalen);
	memcpy(CMSG_DATA(h),&us.fd,cmsgdatalen);
    }

    while (iov.iov_len) {
	ssize_t got=sendmsg(st->privsep_ipcsock_fd,&msg,0);
	if (got<0) {
	    if (errno!=EINTR) fatal_perror("polypath privsep sendmsg");
	    got=0;
	} else {
	    assert(got>0);
	    assert((size_t)got<=iov.iov_len);
	}
	iov.iov_base=(char*)iov.iov_base+got;
	iov.iov_len-=got;
	msg.msg_control=0;
	msg.msg_controllen=0;
    }

 out:
    if (us.fd>=0) close(us.fd);
}

static void child_privsep(struct polypath *st, int ipcsockfd)
/* Privsep child main loop. */
{
    struct pollfd fds[2];

    enter_phase(PHASE_CHILDPERSIST);

    st->privsep_ipcsock_fd=ipcsockfd;
    start_subproc(st,pipe_cloexec,child_monitor,
		  "interface monitor (grandchild)");
    for (;;) {
	int nfds=1;
	int r=polypath_beforepoll(st,fds,&nfds,0);
	assert(nfds==1);
	assert(!r);

	fds[1].fd=st->privsep_ipcsock_fd;
	fds[1].events=POLLIN;

	r=poll(fds,ARRAY_SIZE(fds),-1);

	if (r<0) {
	    if (errno==EINTR) continue;
	    fatal_perror("polypath privsep poll");
	}
	if (fds[1].revents) {
	    if (fds[1].revents & (POLLHUP|POLLIN)) {
		polypath_phase_shutdown(st,PHASE_SHUTDOWN);
		exit(0);
	    }
	    fatal("polypath privsep poll parent socket revents=%#x",
		  fds[1].revents);
	}
	if (fds[0].revents & POLLNVAL)
	    fatal("polypath privsep poll child socket POLLNVAL");
	afterpoll_monitor(st,fds,privsep_handle_ifaddr);
    }
}

static void privsep_socketpair(int *fd)
{
    int r=socketpair(AF_UNIX,SOCK_STREAM,0,fd);
    if (r) fatal_perror("socketpair(AF_UNIX,SOCK_STREAM,,)");
    setcloexec(fd[0]);
    setcloexec(fd[1]);
}

static void polypath_phase_startprivsep(void *sst, uint32_t newphase)
{
    struct polypath *st=sst;

    if (!will_droppriv()) {
	add_hook(PHASE_RUN,          polypath_phase_startmonitor,st);
	return;
    }

    start_subproc(st,privsep_socketpair,child_privsep,
		  "socket generator (privsep interface handler)");

    BUF_FREE(&st->lbuf);
    buffer_destroy(&st->lbuf);
    buffer_new(&st->lbuf,sizeof(struct privsep_mdata));
    BUF_ALLOC(&st->lbuf,"polypath mdata buf");
    st->privsep_incoming_fd=-1;

    register_for_poll(st,polypath_beforepoll,
		      polypath_afterpoll_privsep,"polypath");
}

static void polypath_phase_shutdown(void *sst, uint32_t newphase)
{
    struct polypath *st=sst;
    if (st->monitor_pid) {
	assert(st->monitor_pid>0);
	kill(st->monitor_pid,SIGTERM);
    }
}

static void polypath_phase_childpersist(void *sst, uint32_t newphase)
{
    struct polypath *st=sst;
    struct interf *interf;

    LIST_FOREACH(interf,&st->interfs,entry)
	udp_socks_childpersist(&st->uc,&interf->socks);
}

#undef BAD
#undef BADE

/*----- generic closure and module setup -----*/

static list_t *polypath_apply(closure_t *self, struct cloc loc,
			      dict_t *context, list_t *args)
{
    struct polypath *st;

    COMM_APPLY(st,&st->uc.cc,polypath_,"polypath",loc);
    COMM_APPLY_STANDARD(st,&st->uc.cc,"polypath",args);
    UDP_APPLY_STANDARD(st,&st->uc,"polypath");

    struct udpcommon *uc=&st->uc;
    struct commcommon *cc=&uc->cc;

    st->max_interfs=dict_read_number(d,"max-interfaces",False,"polypath",loc,3);

    st->ifname_pats=dict_read_string_array(d,"interfaces",False,"polypath",
					   cc->loc,0);
    st->permit_loopback=0; /* ifname_wanted reads this */
    ifname_wanted(st,st->uc.cc.loc," "); /* try to check each pattern */

    st->monitor_command=dict_read_string_array(d,"monitor-command",False,
                               "polypath",cc->loc, default_monitor_command);
    if (!st->monitor_command[0])
	cfgfatal(loc,"polypath","no polypath interface monitor-command"
		 " (polypath unsupported on this platform?)\n");

    st->permit_loopback=dict_read_bool(d,"permit-loopback",False,
				       "polypath",cc->loc,False);

    LIST_INIT(&st->interfs);
    buffer_new(&st->lbuf,ADNS_ADDR2TEXT_BUFLEN+100);
    BUF_ALLOC(&st->lbuf,"polypath lbuf");

    st->monitor_fd=-1;
    st->monitor_pid=0;

    add_hook(PHASE_GETRESOURCES, polypath_phase_startprivsep,st);

    add_hook(PHASE_SHUTDOWN,    polypath_phase_shutdown,    st);
    add_hook(PHASE_CHILDPERSIST,polypath_phase_childpersist,st);

    return new_closure(&cc->cl);
}

#endif /* CONFIG_IPV6 */

void polypath_module(dict_t *dict)
{
#ifdef CONFIG_IPV6
    add_closure(dict,"polypath",polypath_apply);
#endif /* CONFIG_IPV6 */
}
