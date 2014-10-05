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

struct notify_list {
    comm_notify_fn *fn;
    void *state;
    struct notify_list *next;
};

struct udp {
    closure_t cl;
    struct comm_if ops;
    struct cloc loc;
    union iaddr addr;
    int fd;
    string_t authbind;
    struct buffer_if *rbuf;
    struct notify_list *notify;
    bool_t use_proxy;
    union iaddr proxy;
};

static const char *addr_to_string(void *commst, const struct comm_addr *ca) {
    struct udp *st=commst;
    static char sbuf[100];

    snprintf(sbuf, sizeof(sbuf), "udp:%s-%s",
            iaddr_to_string(&st->addr), iaddr_to_string(&ca->ia));
    return sbuf;
}

static int udp_beforepoll(void *state, struct pollfd *fds, int *nfds_io,
			  int *timeout_io)
{
    struct udp *st=state;
    if (*nfds_io<1) {
	*nfds_io=1;
	return ERANGE;
    }
    *nfds_io=1;
    fds->fd=st->fd;
    fds->events=POLLIN;
    return 0;
}

static void udp_afterpoll(void *state, struct pollfd *fds, int nfds)
{
    struct udp *st=state;
    union iaddr from;
    socklen_t fromlen;
    struct notify_list *n;
    bool_t done;
    int rv;

    if (nfds && (fds->revents & POLLIN)) {
	do {
	    fromlen=sizeof(from);
	    BUF_ASSERT_FREE(st->rbuf);
	    BUF_ALLOC(st->rbuf,"udp_afterpoll");
	    buffer_init(st->rbuf,calculate_max_start_pad());
	    rv=recvfrom(st->fd, st->rbuf->start,
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
		done=False;
		for (n=st->notify; n; n=n->next) {
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
    struct notify_list *n;
    
    n=safe_malloc(sizeof(*n),"request_notify");
    n->fn=fn;
    n->state=nst;
    n->next=st->notify;
    st->notify=n;
}

static void release_notify(void *commst, void *nst, comm_notify_fn *fn)
{
    struct udp *st=commst;
    struct notify_list *n, **p, *t;

    /* XXX untested */
    p=&st->notify;
    for (n=st->notify; n; )
    {
	if (n->state==nst && n->fn==fn) {
	    t=n;
	    *p=n->next;
	    n=n->next;
	    free(t);
	} else {
	    p=&n->next;
	    n=n->next;
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
	sendto(st->fd,sa,buf->size+8,0,&st->proxy.sa,
	       iaddr_socklen(&st->proxy));
	buf_unprepend(buf,8);
    } else {
	sendto(st->fd, buf->start, buf->size, 0,
	       &dest->ia.sa, iaddr_socklen(&dest->ia));
    }

    return True;
}

static void udp_phase_hook(void *sst, uint32_t new_phase)
{
    struct udp *st=sst;
    union iaddr addr;

    st->fd=socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (st->fd<0) {
	fatal_perror("udp (%s:%d): socket",st->loc.file,st->loc.line);
    }
    if (fcntl(st->fd, F_SETFL, fcntl(st->fd, F_GETFL)|O_NONBLOCK)==-1) {
	fatal_perror("udp (%s:%d): fcntl(set O_NONBLOCK)",
		     st->loc.file,st->loc.line);
    }
    setcloexec(st->fd);

    addr=st->addr;
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
	    char *argv[4], addrstr[9], portstr[5];
	    switch (addr.sa.sa_family) {
	    case AF_INET:
		sprintf(addrstr,"%08lX",(long)addr.sin.sin_addr.s_addr);
		sprintf(portstr,"%04X",addr.sin.sin_port);
		break;
	    default:
		fatal("udp (%s:%d): unsupported address family for authbind",
		      st->loc.file,st->loc.line);
	    }
	    argv[0]=st->authbind;
	    argv[1]=addrstr;
	    argv[2]=portstr;
	    argv[3]=NULL;
	    dup2(st->fd,0);
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
	if (bind(st->fd, &addr.sa, iaddr_socklen(&addr))!=0) {
	    fatal_perror("udp (%s:%d): bind",st->loc.file,st->loc.line);
	}
    }

    register_for_poll(st,udp_beforepoll,udp_afterpoll,1,"udp");
}

static list_t *udp_apply(closure_t *self, struct cloc loc, dict_t *context,
			 list_t *args)
{
    struct udp *st;
    item_t *i,*j;
    dict_t *d;
    list_t *l;
    uint32_t a;

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

    i=list_elem(args,0);
    if (!i || i->type!=t_dict) {
	cfgfatal(st->loc,"udp","first argument must be a dictionary\n");
    }
    d=i->data.dict;

    st->addr.sa.sa_family=AF_INET;
    j=dict_find_item(d,"address",False,"udp",st->loc);
    st->addr.sin.sin_addr.s_addr=j?string_item_to_ipaddr(j, "udp"):INADDR_ANY;
    st->addr.sin.sin_port=dict_read_number(d,"port",True,"udp",st->loc,0);
    st->rbuf=find_cl_if(d,"buffer",CL_BUFFER,True,"udp",st->loc);
    st->authbind=dict_read_string(d,"authbind",False,"udp",st->loc);
    l=dict_lookup(d,"proxy");
    if (l) {
	st->use_proxy=True;
	st->proxy.sa.sa_family=AF_INET;
	i=list_elem(l,0);
	if (!i || i->type!=t_string) {
	    cfgfatal(st->loc,"udp","proxy must supply ""addr"",port\n");
	}
	a=string_item_to_ipaddr(i,"proxy");
	st->proxy.sin.sin_addr.s_addr=htonl(a);
	i=list_elem(l,1);
	if (!i || i->type!=t_number) {
	    cfgfatal(st->loc,"udp","proxy must supply ""addr"",port\n");
	}
	st->proxy.sin.sin_port=htons(i->data.number);
    }

    update_max_start_pad(&comm_max_start_pad, st->use_proxy ? 8 : 0);

    add_hook(PHASE_GETRESOURCES,udp_phase_hook,st);

    return new_closure(&st->cl);
}

void udp_module(dict_t *dict)
{
    add_closure(dict,"udp",udp_apply);
}
