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

#define MAX_SOCKETS 3 /* 2 ought to do really */

struct udpsock {
    union iaddr addr;
    int fd;
};

struct udp {
    closure_t cl;
    struct comm_if ops;
    struct cloc loc;
    int n_socks;
    struct udpsock socks[MAX_SOCKETS];
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
    static char sbuf[100];
    int ix=ca->ix>=0 ? ca->ix : 0;

    assert(ix>=0 && ix<st->n_socks);
    snprintf(sbuf, sizeof(sbuf), "udp:%s%s-%s",
	     iaddr_to_string(&st->socks[ix].addr),
	     ca->ix<0 ? "&" : "",
	     iaddr_to_string(&ca->ia));
    return sbuf;
}

static int udp_beforepoll(void *state, struct pollfd *fds, int *nfds_io,
			  int *timeout_io)
{
    int i;
    struct udp *st=state;
    if (*nfds_io<st->n_socks) {
	*nfds_io=st->n_socks;
	return ERANGE;
    }
    *nfds_io=st->n_socks;
    for (i=0; i<st->n_socks; i++) {
	fds[i].fd=st->socks[i].fd;
	fds[i].events=POLLIN;
    }
    return 0;
}

static void udp_afterpoll(void *state, struct pollfd *fds, int nfds)
{
    struct udp *st=state;
    union iaddr from;
    socklen_t fromlen;
    struct comm_notify_entry *n;
    bool_t done;
    int rv;
    int i;

    for (i=0; i<st->n_socks; i++) {
	if (i>=nfds) continue;
	if (!(fds[i].revents & POLLIN)) continue;
	assert(fds[i].fd == st->socks[i].fd);
	int fd=st->socks[i].fd;
	do {
	    fromlen=sizeof(from);
	    BUF_ASSERT_FREE(st->rbuf);
	    BUF_ALLOC(st->rbuf,"udp_afterpoll");
	    buffer_init(st->rbuf,calculate_max_start_pad());
	    rv=recvfrom(fd, st->rbuf->start,
			buf_remaining_space(st->rbuf),
			0, &from.sa, &fromlen);
	    if (rv>0) {
		st->rbuf->size=rv;
		if (st->use_proxy) {
		    /* Check that the packet came from our poxy server;
		       we shouldn't be contacted directly by anybody else
		       (since they can trivially forge source addresses) */
		    if (!iaddr_equal(&from,&st->proxy)) {
			Message(M_INFO,"udp: received packet that's not "
				"from the proxy\n");
			BUF_FREE(st->rbuf);
			continue;
		    }
		    /* proxy protocol supports ipv4 transport only */
		    from.sa.sa_family=AF_INET;
		    memcpy(&from.sin.sin_addr,buf_unprepend(st->rbuf,4),4);
		    buf_unprepend(st->rbuf,2);
		    memcpy(&from.sin.sin_port,buf_unprepend(st->rbuf,2),2);
		}
		struct comm_addr ca;
		ca.comm=&st->ops;
		ca.ia=from;
		ca.ix=i;
		done=False;
		LIST_FOREACH(n, &st->notify, entry) {
		    if (n->fn(n->state, st->rbuf, &ca)) {
			done=True;
			break;
		    }
		}
		if (!done) {
		    uint32_t msgtype;
		    if (st->rbuf->size>12 /* prevents traffic amplification */
			&& ((msgtype=get_uint32(st->rbuf->start+8))
			    != LABEL_NAK)) {
			uint32_t source,dest;
			/* Manufacture and send NAK packet */
			source=get_uint32(st->rbuf->start); /* Us */
			dest=get_uint32(st->rbuf->start+4); /* Them */
			send_nak(&ca,source,dest,msgtype,st->rbuf,"unwanted");
		    }
		    BUF_FREE(st->rbuf);
		}
		BUF_ASSERT_FREE(st->rbuf);
	    } else {
		BUF_FREE(st->rbuf);
	    }
	} while (rv>=0);
    }
}

static void request_notify(void *commst, void *nst, comm_notify_fn *fn)
{
    struct udp *st=commst;
    struct comm_notify_entry *n;
    
    n=safe_malloc(sizeof(*n),"request_notify");
    n->fn=fn;
    n->state=nst;
    LIST_INSERT_HEAD(&st->notify, n, entry);
}

static void release_notify(void *commst, void *nst, comm_notify_fn *fn)
{
    struct udp *st=commst;
    struct comm_notify_entry *n, *t;

    /* XXX untested */
    LIST_FOREACH_SAFE(n, &st->notify, entry, t) {
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
    uint8_t *sa;

    if (st->use_proxy) {
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
	sendto(st->socks[0].fd,sa,buf->size+8,0,&st->proxy.sa,
	       iaddr_socklen(&st->proxy));
	buf_unprepend(buf,8);
    } else {
	int i,r;
	bool_t allunsupported=True;
	for (i=0; i<st->n_socks; i++) {
	    if (dest->ia.sa.sa_family != st->socks[i].addr.sa.sa_family)
		/* no point even trying */
		continue;
	    r=sendto(st->socks[i].fd, buf->start, buf->size, 0,
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
    us->fd=socket(addr->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (us->fd<0) {
	fatal_perror("udp (%s:%d): socket",st->loc.file,st->loc.line);
    }
    if (fcntl(us->fd, F_SETFL, fcntl(us->fd, F_GETFL)|O_NONBLOCK)==-1) {
	fatal_perror("udp (%s:%d): fcntl(set O_NONBLOCK)",
		     st->loc.file,st->loc.line);
    }
    setcloexec(us->fd);
#ifdef CONFIG_IPV6
    if (addr->sa.sa_family==AF_INET6) {
	int r;
	int optval=1;
	socklen_t optlen=sizeof(optval);
	r=setsockopt(us->fd,IPPROTO_IPV6,IPV6_V6ONLY,&optval,optlen);
	if (r) fatal_perror("udp (%s:%d): setsockopt(,IPV6_V6ONLY,&1,)",
			    st->loc.file,st->loc.line);
    }
#endif

    if (st->authbind) {
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
		      st->loc.file,st->loc.line);
	    }
	    sprintf(portstr,"%04X",port);
	    argv[0]=st->authbind;
	    argv[1]=addrstr;
	    argv[2]=portstr;
	    argv[3]=(char*)addrfam;
	    argv[4]=NULL;
	    dup2(us->fd,0);
	    execvp(st->authbind,argv);
	    _exit(255);
	}
	while (waitpid(c,&status,0)==-1) {
	    if (errno==EINTR) continue;
	    fatal_perror("udp (%s:%d): authbind",st->loc.file,st->loc.line);
	}
	if (WIFSIGNALED(status)) {
	    fatal("udp (%s:%d): authbind died on signal %d",st->loc.file,
		  st->loc.line, WTERMSIG(status));
	}
	if (WIFEXITED(status) && WEXITSTATUS(status)!=0) {
	    fatal("udp (%s:%d): authbind died with status %d",st->loc.file,
		  st->loc.line, WEXITSTATUS(status));
	}
    } else {
	if (bind(us->fd, &addr->sa, iaddr_socklen(addr))!=0) {
	    fatal_perror("udp (%s:%d): bind",st->loc.file,st->loc.line);
	}
    }
}

static void udp_phase_hook(void *sst, uint32_t new_phase)
{
    struct udp *st=sst;
    int i;
    for (i=0; i<st->n_socks; i++)
	udp_make_socket(st,&st->socks[i]);

    register_for_poll(st,udp_beforepoll,udp_afterpoll,MAX_SOCKETS,"udp");
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
    st->loc=loc;
    st->cl.description="udp";
    st->cl.type=CL_COMM;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.request_notify=request_notify;
    st->ops.release_notify=release_notify;
    st->ops.sendmsg=udp_sendmsg;
    st->ops.addr_to_string=addr_to_string;
    st->use_proxy=False;
    LIST_INIT(&st->notify);

    item=list_elem(args,0);
    if (!item || item->type!=t_dict) {
	cfgfatal(st->loc,"udp","first argument must be a dictionary\n");
    }
    d=item->data.dict;

    int port=dict_read_number(d,"port",True,"udp",st->loc,0);

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
    st->n_socks=caddrl ? list_length(caddrl) : (int)ARRAY_SIZE(defaultaddrs);
    if (st->n_socks<=0 || st->n_socks>MAX_SOCKETS)
	cfgfatal(st->loc,"udp","`address' must be 1..%d addresses",
		 MAX_SOCKETS);

    for (i=0; i<st->n_socks; i++) {
	struct udpsock *us=&st->socks[i];
	if (!list_length(caddrl)) {
	    us->addr=defaultaddrs[i];
	} else {
	    string_item_to_iaddr(list_elem(caddrl,i),port,&us->addr,"udp");
	}
	us->fd=-1;
    }

    st->rbuf=find_cl_if(d,"buffer",CL_BUFFER,True,"udp",st->loc);
    st->authbind=dict_read_string(d,"authbind",False,"udp",st->loc);
    l=dict_lookup(d,"proxy");
    if (l) {
	st->use_proxy=True;
	st->proxy.sa.sa_family=AF_INET;
	item=list_elem(l,0);
	if (!item || item->type!=t_string) {
	    cfgfatal(st->loc,"udp","proxy must supply ""addr"",port\n");
	}
	a=string_item_to_ipaddr(item,"proxy");
	st->proxy.sin.sin_addr.s_addr=htonl(a);
	item=list_elem(l,1);
	if (!item || item->type!=t_number) {
	    cfgfatal(st->loc,"udp","proxy must supply ""addr"",port\n");
	}
	st->proxy.sin.sin_port=htons(item->data.number);
    }

    update_max_start_pad(&comm_max_start_pad, st->use_proxy ? 8 : 0);

    add_hook(PHASE_GETRESOURCES,udp_phase_hook,st);

    return new_closure(&st->cl);
}

void udp_module(dict_t *dict)
{
    add_closure(dict,"udp",udp_apply);
}
