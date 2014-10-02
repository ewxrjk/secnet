/* UDP send/receive module for secnet */

/* This module enables sites to communicate by sending UDP
 * packets. When an instance of the module is created we can
 * optionally bind to a particular local IP address (not implemented
 * yet).
 *
 * Packets are offered to registered receivers in turn. Once one
 * accepts it, it isn't offered to any more. */

#include "secnet.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"
#include "magic.h"
#include "unaligned.h"
#include "ipaddr.h"
#include "magic.h"

static beforepoll_fn udp_beforepoll;
static afterpoll_fn udp_afterpoll;
static comm_request_notify_fn request_notify;
static comm_release_notify_fn release_notify;
static comm_sendmsg_fn udp_sendmsg;

struct comm_notify_entry {
    comm_notify_fn *fn;
    void *state;
    LIST_ENTRY(comm_notify_entry) entry;
};
LIST_HEAD(comm_notify_list, comm_notify_entry) notify;

#define UDP_MAX_SOCKETS 3 /* 2 ought to do really */

struct udpsock {
    union iaddr addr;
    int fd;
};

struct udp {
    closure_t cl;
    struct comm_if ops;
    struct cloc loc;
    int n_socks;
    struct udpsock socks[UDP_MAX_SOCKETS];
    string_t authbind;
    struct buffer_if *rbuf;
    struct comm_notify_list notify;
    bool_t use_proxy;
    union iaddr proxy;
};

/*
 * Re comm_addr.ix: This field allows us to note in the comm_addr
 * which socket an incoming packet was received on.  This is required
 * for conveniently logging the actual source of a packet.  But the ix
 * does not formally form part of the address: it is not used when
 * sending, nor when comparing two comm_addrs.
 *
 * The special value -1 means that the comm_addr was constructed by
 * another module in secnet (eg the resolver), rather than being a
 * description of the source of an incoming packet.
 */

static const char *addr_to_string(void *commst, const struct comm_addr *ca) {
    struct udp *st=commst;
    struct udp *socks=st; /* for now */
    static char sbuf[100];
    int ix=ca->ix>=0 ? ca->ix : 0;

    assert(ix>=0 && ix<socks->n_socks);
    snprintf(sbuf, sizeof(sbuf), "udp:%s%s-%s",
	     iaddr_to_string(&socks->socks[ix].addr),
	     ca->ix<0 ? "&" : "",
	     iaddr_to_string(&ca->ia));
    return sbuf;
}

static int udp_beforepoll(void *state, struct pollfd *fds, int *nfds_io,
			  int *timeout_io)
{
    int i;
    struct udp *st=state;
    struct udp *socks=st; /* for now */
    BEFOREPOLL_WANT_FDS(socks->n_socks);
    for (i=0; i<socks->n_socks; i++) {
	fds[i].fd=socks->socks[i].fd;
	fds[i].events=POLLIN;
    }
    return 0;
}

static void udp_afterpoll(void *state, struct pollfd *fds, int nfds)
{
    struct udp *st=state;
    struct udp *socks=st; /* for now */
    struct udp *cc=st; /* for now */
    struct udp *uc=st; /* for now */
    union iaddr from;
    socklen_t fromlen;
    struct comm_notify_entry *n;
    bool_t done;
    int rv;
    int i;

    for (i=0; i<st->n_socks; i++) {
	if (i>=nfds) continue;
	if (!(fds[i].revents & POLLIN)) continue;
	assert(fds[i].fd == socks->socks[i].fd);
	int fd=socks->socks[i].fd;
	do {
	    fromlen=sizeof(from);
	    BUF_ASSERT_FREE(cc->rbuf);
	    BUF_ALLOC(cc->rbuf,"udp_afterpoll");
	    buffer_init(cc->rbuf,calculate_max_start_pad());
	    rv=recvfrom(fd, cc->rbuf->start,
			buf_remaining_space(cc->rbuf),
			0, &from.sa, &fromlen);
	    if (rv>0) {
		cc->rbuf->size=rv;
		if (uc->use_proxy) {
		    /* Check that the packet came from our poxy server;
		       we shouldn't be contacted directly by anybody else
		       (since they can trivially forge source addresses) */
		    if (!iaddr_equal(&from,&uc->proxy)) {
			Message(M_INFO,"udp: received packet that's not "
				"from the proxy\n");
			BUF_FREE(cc->rbuf);
			continue;
		    }
		    /* proxy protocol supports ipv4 transport only */
		    from.sa.sa_family=AF_INET;
		    BUF_GET_BYTES(unprepend,cc->rbuf,&from.sin.sin_addr,4);
		    buf_unprepend(cc->rbuf,2);
		    BUF_GET_BYTES(unprepend,cc->rbuf,&from.sin.sin_port,2);
		}
		struct comm_addr ca;
		ca.comm=&cc->ops;
		ca.ia=from;
		ca.ix=i;
		done=False;
		LIST_FOREACH(n, &cc->notify, entry) {
		    if (n->fn(n->state, cc->rbuf, &ca)) {
			done=True;
			break;
		    }
		}
		if (!done) {
		    uint32_t msgtype;
		    if (cc->rbuf->size>12 /* prevents traffic amplification */
			&& ((msgtype=get_uint32(cc->rbuf->start+8))
			    != LABEL_NAK)) {
			uint32_t source,dest;
			/* Manufacture and send NAK packet */
			source=get_uint32(cc->rbuf->start); /* Us */
			dest=get_uint32(cc->rbuf->start+4); /* Them */
			send_nak(&ca,source,dest,msgtype,cc->rbuf,"unwanted");
		    }
		    BUF_FREE(cc->rbuf);
		}
		BUF_ASSERT_FREE(cc->rbuf);
	    } else {
		BUF_FREE(cc->rbuf);
	    }
	} while (rv>=0);
    }
}

static void request_notify(void *commst, void *nst, comm_notify_fn *fn)
{
    struct udp *st=commst;
    struct udp *cc=st; /* for now */
    struct comm_notify_entry *n;
    
    n=safe_malloc(sizeof(*n),"request_notify");
    n->fn=fn;
    n->state=nst;
    LIST_INSERT_HEAD(&cc->notify, n, entry);
}

static void release_notify(void *commst, void *nst, comm_notify_fn *fn)
{
    struct udp *st=commst;
    struct udp *cc=st; /* for now */
    struct comm_notify_entry *n, *t;

    /* XXX untested */
    LIST_FOREACH_SAFE(n, &cc->notify, entry, t) {
	if (n->state==nst && n->fn==fn) {
	    LIST_REMOVE(n, entry);
	    free(n);
	}
    }
}

static bool_t udp_sendmsg(void *commst, struct buffer_if *buf,
			  const struct comm_addr *dest)
{
    struct udp *st=commst;
    struct udp *uc=st; /* for now */
    struct udp *socks=st; /* for now */
    uint8_t *sa;

    if (uc->use_proxy) {
	sa=buf_prepend(buf,8);
	if (dest->ia.sa.sa_family != AF_INET) {
	    Message(M_INFO,
               "udp: proxy means dropping outgoing non-IPv4 packet to %s\n",
		    iaddr_to_string(&dest->ia));
	    return False;
	}
	memcpy(sa,&dest->ia.sin.sin_addr,4);
	memset(sa+4,0,4);
	memcpy(sa+6,&dest->ia.sin.sin_port,2);
	sendto(socks->socks[0].fd,sa,buf->size+8,0,&uc->proxy.sa,
	       iaddr_socklen(&uc->proxy));
	buf_unprepend(buf,8);
    } else {
	int i,r;
	bool_t allunsupported=True;
	for (i=0; i<socks->n_socks; i++) {
	    if (dest->ia.sa.sa_family != socks->socks[i].addr.sa.sa_family)
		/* no point even trying */
		continue;
	    r=sendto(socks->socks[i].fd, buf->start, buf->size, 0,
		     &dest->ia.sa, iaddr_socklen(&dest->ia));
	    if (r>=0) return True;
	    if (!(errno==EAFNOSUPPORT || errno==ENETUNREACH))
		/* who knows what that error means? */
		allunsupported=False;
	}
	return !allunsupported; /* see doc for comm_sendmsg_fn in secnet.h */
    }

    return True;
}

static void udp_make_socket(struct udp *st, struct udpsock *us)
{
    const union iaddr *addr=&us->addr;
    struct udp *cc=st; /* for now */
    struct udp *uc=st; /* for now */
    us->fd=socket(addr->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (us->fd<0) {
	fatal_perror("udp (%s:%d): socket",cc->loc.file,cc->loc.line);
    }
    if (fcntl(us->fd, F_SETFL, fcntl(us->fd, F_GETFL)|O_NONBLOCK)==-1) {
	fatal_perror("udp (%s:%d): fcntl(set O_NONBLOCK)",
		     cc->loc.file,cc->loc.line);
    }
    setcloexec(us->fd);
#ifdef CONFIG_IPV6
    if (addr->sa.sa_family==AF_INET6) {
	int r;
	int optval=1;
	socklen_t optlen=sizeof(optval);
	r=setsockopt(us->fd,IPPROTO_IPV6,IPV6_V6ONLY,&optval,optlen);
	if (r) fatal_perror("udp (%s:%d): setsockopt(,IPV6_V6ONLY,&1,)",
			    cc->loc.file,cc->loc.line);
    }
#endif

    if (uc->authbind) {
	pid_t c;
	int status;

	/* XXX this fork() and waitpid() business needs to be hidden
	   in some system-specific library functions. */
	c=fork();
	if (c==-1) {
	    fatal_perror("udp_phase_hook: fork() for authbind");
	}
	if (c==0) {
	    char *argv[5], addrstr[33], portstr[5];
	    const char *addrfam;
	    int port;
	    switch (addr->sa.sa_family) {
	    case AF_INET:
		sprintf(addrstr,"%08lX",(long)addr->sin.sin_addr.s_addr);
		port=addr->sin.sin_port;
		addrfam=NULL;
		break;
#ifdef CONFIG_IPV6
	    case AF_INET6: {
		int i;
		for (i=0; i<16; i++)
		    sprintf(addrstr+i*2,"%02X",addr->sin6.sin6_addr.s6_addr[i]);
		port=addr->sin6.sin6_port;
		addrfam="6";
		break;
	    }
#endif /*CONFIG_IPV6*/
	    default:
		fatal("udp (%s:%d): unsupported address family for authbind",
		      cc->loc.file,cc->loc.line);
	    }
	    sprintf(portstr,"%04X",port);
	    argv[0]=uc->authbind;
	    argv[1]=addrstr;
	    argv[2]=portstr;
	    argv[3]=(char*)addrfam;
	    argv[4]=NULL;
	    dup2(us->fd,0);
	    execvp(uc->authbind,argv);
	    _exit(255);
	}
	while (waitpid(c,&status,0)==-1) {
	    if (errno==EINTR) continue;
	    fatal_perror("udp (%s:%d): authbind",cc->loc.file,cc->loc.line);
	}
	if (WIFSIGNALED(status)) {
	    fatal("udp (%s:%d): authbind died on signal %d",cc->loc.file,
		  cc->loc.line, WTERMSIG(status));
	}
	if (WIFEXITED(status) && WEXITSTATUS(status)!=0) {
	    fatal("udp (%s:%d): authbind died with status %d",cc->loc.file,
		  cc->loc.line, WEXITSTATUS(status));
	}
    } else {
	if (bind(us->fd, &addr->sa, iaddr_socklen(addr))!=0) {
	    fatal_perror("udp (%s:%d): bind",cc->loc.file,cc->loc.line);
	}
    }
}

static void udp_phase_hook(void *sst, uint32_t new_phase)
{
    struct udp *st=sst;
    struct udp *socks=st; /* for now */
    int i;
    for (i=0; i<socks->n_socks; i++)
	udp_make_socket(st,&socks->socks[i]);

    register_for_poll(st,udp_beforepoll,udp_afterpoll,"udp");
}

static list_t *udp_apply(closure_t *self, struct cloc loc, dict_t *context,
			 list_t *args)
{
    struct udp *st;
    item_t *item;
    list_t *caddrl;
    dict_t *d;
    list_t *l;
    uint32_t a;
    int i;

    st=safe_malloc(sizeof(*st),"udp_apply(st)");
    struct udp *cc=st; /* for now */
    struct udp *uc=st; /* for now */
    struct udp *socks=st; /* for now */
    cc->loc=loc;
    cc->cl.description="udp";
    cc->cl.type=CL_COMM;
    cc->cl.apply=NULL;
    cc->cl.interface=&cc->ops;
    cc->ops.st=st;
    cc->ops.request_notify=request_notify;
    cc->ops.release_notify=release_notify;
    cc->ops.sendmsg=udp_sendmsg;
    cc->ops.addr_to_string=addr_to_string;
    uc->use_proxy=False;
    LIST_INIT(&cc->notify);

    item=list_elem(args,0);
    if (!item || item->type!=t_dict) {
	cfgfatal(cc->loc,"udp","first argument must be a dictionary\n");
    }
    d=item->data.dict;

    int port=dict_read_number(d,"port",True,"udp",cc->loc,0);

    union iaddr defaultaddrs[] = {
#ifdef CONFIG_IPV6
	{ .sin6 = { .sin6_family=AF_INET6,
		    .sin6_port=htons(port),
		    .sin6_addr=IN6ADDR_ANY_INIT } },
#endif
	{ .sin = { .sin_family=AF_INET,
		   .sin_port=htons(port),
		   .sin_addr= { .s_addr=INADDR_ANY } } }
    };

    caddrl=dict_lookup(d,"address");
    socks->n_socks=caddrl ? list_length(caddrl) : (int)ARRAY_SIZE(defaultaddrs);
    if (socks->n_socks<=0 || socks->n_socks>UDP_MAX_SOCKETS)
	cfgfatal(cc->loc,"udp","`address' must be 1..%d addresses",
		 UDP_MAX_SOCKETS);

    for (i=0; i<socks->n_socks; i++) {
	struct udpsock *us=&socks->socks[i];
	if (!list_length(caddrl)) {
	    us->addr=defaultaddrs[i];
	} else {
	    string_item_to_iaddr(list_elem(caddrl,i),port,&us->addr,"udp");
	}
	us->fd=-1;
    }

    cc->rbuf=find_cl_if(d,"buffer",CL_BUFFER,True,"udp",cc->loc);
    uc->authbind=dict_read_string(d,"authbind",False,"udp",cc->loc);
    l=dict_lookup(d,"proxy");
    if (l) {
	uc->use_proxy=True;
	uc->proxy.sa.sa_family=AF_INET;
	item=list_elem(l,0);
	if (!item || item->type!=t_string) {
	    cfgfatal(cc->loc,"udp","proxy must supply ""addr"",port\n");
	}
	a=string_item_to_ipaddr(item,"proxy");
	uc->proxy.sin.sin_addr.s_addr=htonl(a);
	item=list_elem(l,1);
	if (!item || item->type!=t_number) {
	    cfgfatal(cc->loc,"udp","proxy must supply ""addr"",port\n");
	}
	uc->proxy.sin.sin_port=htons(item->data.number);
    }

    update_max_start_pad(&comm_max_start_pad, uc->use_proxy ? 8 : 0);

    add_hook(PHASE_GETRESOURCES,udp_phase_hook,st);

    return new_closure(&cc->cl);
}

void udp_module(dict_t *dict)
{
    add_closure(dict,"udp",udp_apply);
}
