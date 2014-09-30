/* polypath
 * send/receive module for secnet
 * for multi-route setups */

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
    LIST_HEAD(,interf) interfs;
    struct buffer_if lbuf;
    int monitor_fd;
    pid_t monitor_pid;
};

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
				 const char *ifname, bool_t *want_io,
				 const char *const *pats) {
    /* Returns True iff we found a list entry, in which case *want_io
     * is set to the sense of that entry.  Otherwise *want_io is set
     * to the sense of the last entry, or unchanged if there were no pats. */
    if (!pats)
	return False;
    const char *const *pati;
    for (pati=pats; *pati; pati++) {
	const char *pat=*pati;
	if (*pat=='!') { *want_io=False; pat++; }
	else if (*pat=='+') { *want_io=True; pat++; }
	else if (*pat=='*' || isalnum((unsigned char)*pat)) { *want_io=True; }
	else cfgfatal(loc,"polypath","invalid interface name pattern `%s'",pat);
	int match=fnmatch(pat,ifname,0);
	if (match==0) return True;
	if (match!=FNM_NOMATCH)
	    cfgfatal(loc,"polypath","fnmatch failed! (pattern `%s')",pat);
    }
    return False;
}

static bool_t ifname_wanted(struct polypath *st, struct cloc loc,
			    const char *ifname) {
    bool_t want=False; /* pretend an empty cfg ends with !<doesn'tmatch> */
    if (ifname_search_pats(st,loc,ifname,&want, st->ifname_pats))
	return want;
    if (want) /* last pattern was positive, do not search default */
	return False;
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
#define BAD(m)     do{ bad(st,badctx,m,0);  goto out; }while(0)
#define BADE(m,ev) do{ bad(st,badctx,m,ev); goto out; }while(0)
typedef void bad_fn_type(struct polypath *st, void *badctx,
			 const char* m, int ev);

typedef void polypath_ppml_callback_type(struct polypath *st,
          bad_fn_type *bad, void *badctx,
          bool_t add, const char *ifname, const char *ifaddr,
          const union iaddr *ia, int fd /* -1 if none yet */);

struct ppml_bad_ctx {
    const char *orgl;
    char *undospace;
};

static void ppml_bad(struct polypath *st, void *badctx, const char *m, int ev)
{
    struct ppml_bad_ctx *bc=badctx;
    if (bc->undospace)
	*(bc->undospace)=' ';
    lg_perror(LG,M_WARNING,ev,
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

    if (!ifname_wanted(st,st->uc.cc.loc,ifname))
	DONT("unwanted interface name");

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
    callback(st, bad,badctx, add,ifname,ifaddr,&ia,-1);

 out:;
}

static void dump_pria(struct polypath *st, const char *ifname)
{
#ifdef POLYPATH_DEBUG
    struct interf *interf;
    if (ifname)
	lg_perror(LG,M_DEBUG,0, "polypath record ifaddr `%s'",ifname);
    LIST_FOREACH(interf, &st->interfs, entry) {
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
				   bool_t add, const char *ifname,
				   const char *ifaddr,
				   const union iaddr *ia, int fd)
{
    struct udpcommon *uc=&st->uc;
    struct interf *interf=0;
    struct udpsock *us=0;

    dump_pria(st,ifname);

    int n_ifs=0;
    LIST_FOREACH(interf,&st->interfs,entry) {
	if (!strcmp(interf->name,ifname))
	    goto found_interf;
	n_ifs++;
    }
    /* not found */
    if (n_ifs==st->max_interfs) BAD("too many interfaces");
    interf=malloc(sizeof(*interf));
    if (!interf) BADE("malloc for new interface",errno);
    interf->name=0;
    interf->socks.n_socks=0;
    FILLZERO(interf->experienced_xmit_noaf);
    LIST_INSERT_HEAD(&st->interfs,interf,entry);
    udp_socks_register(&st->uc,&interf->socks);
    interf->name=strdup(ifname);
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
	    FILLZERO(us->experienced);
	    us->fd=fd;
	    fd=-1;
	}
	interf->socks.n_socks++;
	us=0; /* do not destroy this socket during `out' */
	lg_perror(LG,M_INFO,0,"using %s %s",ifname,ifaddr);
    } else {
	int i;
	for (i=0; i<interf->socks.n_socks; i++)
	    if (!memcmp(&interf->socks.socks[i].addr,ia,sizeof(*ia)))
		goto address_remove_found;
	BAD("address to remove not found");
    address_remove_found:
	lg_perror(LG,M_INFO,0,"removed %s %s",ifname,ifaddr);
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

    dump_pria(st,0);
}

static void polypath_afterpoll(void *state, struct pollfd *fds, int nfds)
{
    struct polypath *st=state;
    enum async_linebuf_result alr;
    const char *emsg;
    int status;

    if (nfds<1) return;

    while ((alr=async_linebuf_read(fds,&st->lbuf,&emsg)) == async_linebuf_ok)
	polypath_process_monitor_line(st,st->lbuf.base,
				      polypath_record_ifaddr);

    if (alr==async_linebuf_nothing)
	return;

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

/* Actual udp packet sending work */
static bool_t polypath_sendmsg(void *commst, struct buffer_if *buf,
			  const struct comm_addr *dest)
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
	    udp_sock_experienced(0,&st->uc, interf->name,us,
				 1,af, r,errno);
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

static void polypath_phase_startmonitor(void *sst, uint32_t newphase)
{
    struct polypath *st=sst;
    int pfds[2];

    assert(!st->monitor_pid);
    assert(st->monitor_fd<0);

    pipe_cloexec(pfds);

    pid_t pid=fork();
    if (!pid) {
	afterfork();
	dup2(pfds[1],1);
	execvp(st->monitor_command[0],(char**)st->monitor_command);
	fprintf(stderr,"secnet: cannot execute %s: %s\n",
		st->monitor_command[0], strerror(errno));
	exit(-1);
    }
    if (pid<0)
	fatal_perror("%s: failed to fork for interface monitor",
		     st->uc.cc.cl.description);

    close(pfds[1]);
    st->monitor_pid=pid;
    st->monitor_fd=pfds[0];
    setnonblock(st->monitor_fd);

    register_for_poll(st,polypath_beforepoll,polypath_afterpoll,"polypath");
}

static void polypath_phase_shutdown(void *sst, uint32_t newphase)
{
    struct polypath *st=sst;
    if (st->monitor_pid) {
	assert(st->monitor_pid>0);
	kill(st->monitor_pid,SIGTERM);
    }
}

#undef BAD
#undef BADE

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

    add_hook(PHASE_RUN,         polypath_phase_startmonitor,st);
    add_hook(PHASE_SHUTDOWN,    polypath_phase_shutdown,    st);

    return new_closure(&cc->cl);
}

#endif /* CONFIG_IPV6 */

void polypath_module(dict_t *dict)
{
#ifdef CONFIG_IPV6
    add_closure(dict,"polypath",polypath_apply);
#endif /* CONFIG_IPV6 */
}
