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
#include "util.h"
#include "unaligned.h"
#include "ipaddr.h"

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
    uint16_t port;
    int fd;
    string_t authbind;
    struct buffer_if *rbuf;
    struct notify_list *notify;
    bool_t use_proxy;
    struct sockaddr_in proxy;
};

static int udp_beforepoll(void *state, struct pollfd *fds, int *nfds_io,
			  int *timeout_io, const struct timeval *tv,
			  uint64_t *now)
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

static void udp_afterpoll(void *state, struct pollfd *fds, int nfds,
			  const struct timeval *tv, uint64_t *now)
{
    struct udp *st=state;
    struct sockaddr_in from;
    int fromlen;
    struct notify_list *n;
    bool_t done;
    int rv;

    if (nfds && (fds->revents & POLLIN)) {
	do {
	    fromlen=sizeof(from);
	    BUF_ASSERT_FREE(st->rbuf);
	    BUF_ALLOC(st->rbuf,"udp_afterpoll");
	    rv=recvfrom(st->fd, st->rbuf->start, st->rbuf->len, 0,
			(struct sockaddr *)&from, &fromlen);
	    if (rv>0) {
		st->rbuf->size=rv;
		if (st->use_proxy) {
		    /* Check that the packet came from our poxy server;
		       we shouldn't be contacted directly by anybody else
		       (since they can trivially forge source addresses) */
		    if (memcmp(&from.sin_addr,&st->proxy.sin_addr,4)!=0 ||
			memcmp(&from.sin_port,&st->proxy.sin_port,2)!=0) {
			Message(M_INFO,"udp: received packet that's not "
				"from the proxy\n");
			BUF_FREE(st->rbuf);
			continue;
		    }
		    memcpy(&from.sin_addr,buf_unprepend(st->rbuf,4),4);
		    buf_unprepend(st->rbuf,2);
		    memcpy(&from.sin_port,buf_unprepend(st->rbuf,2),2);
		}
		done=False;
		for (n=st->notify; n; n=n->next) {
		    if (n->fn(n->state, st->rbuf, &from)) {
			done=True;
			break;
		    }
		}
		if (!done) {
		    uint32_t source,dest;
		    /* Manufacture and send NAK packet */
		    source=get_uint32(st->rbuf->start); /* Us */
		    dest=get_uint32(st->rbuf->start+4); /* Them */
		    Message(M_INFO,"udp (port %d): sending NAK\n",st->port);
		    buffer_init(st->rbuf,0);
		    buf_append_uint32(st->rbuf,dest);
		    buf_append_uint32(st->rbuf,source);
		    buf_append_uint32(st->rbuf,0); /* NAK is msg type 0 */
		    sendto(st->fd, st->rbuf->start, st->rbuf->size, 0,
			   (struct sockaddr *)&from, sizeof(from));
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
			  struct sockaddr_in *dest)
{
    struct udp *st=commst;
    uint8_t *sa;

    if (st->use_proxy) {
	sa=buf->start-8;
	memcpy(sa,&dest->sin_addr,4);
	memset(sa+4,0,4);
	memcpy(sa+6,&dest->sin_port,2);
	sendto(st->fd,sa,buf->size+8,0,(struct sockaddr *)&st->proxy,
	       sizeof(st->proxy));
    } else {
	sendto(st->fd, buf->start, buf->size, 0,
	       (struct sockaddr *)dest, sizeof(*dest));
    }

    return True;
}

static void udp_phase_hook(void *sst, uint32_t new_phase)
{
    struct udp *st=sst;
    struct sockaddr_in addr;

    st->fd=socket(AF_INET, SOCK_DGRAM, 0);
    if (st->fd<0) {
	fatal_perror("udp (%s:%d): socket",st->loc.file,st->loc.line);
    }
    if (fcntl(st->fd, F_SETFL, fcntl(st->fd, F_GETFL)|O_NONBLOCK)==-1) {
	fatal_perror("udp (%s:%d): fcntl(set O_NONBLOCK)",
		     st->loc.file,st->loc.line);
    }
    if (fcntl(st->fd, F_SETFD, FD_CLOEXEC)==-1) {
	fatal_perror("udp (%s:%d): fcntl(set FD_CLOEXEC)",
		     st->loc.file,st->loc.line);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_port=htons(st->port);
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
	    char *argv[4];
	    argv[0]=st->authbind;
	    argv[1]=strdup("00000000");
	    if (!argv[1]) exit(ENOMEM);
	    argv[2]=alloca(8);
	    if (!argv[2]) exit(ENOMEM);
	    sprintf(argv[2],"%04X",htons(st->port));
	    argv[3]=NULL;
	    dup2(st->fd,0);
	    execvp(st->authbind,argv);
	    exit(ENOEXEC);
	}
	waitpid(c,&status,0);
	if (WEXITSTATUS(status)!=0) {
	    errno=WEXITSTATUS(status);
	    fatal_perror("udp (%s:%d): authbind",st->loc.file,st->loc.line);
	}
    } else {
	if (bind(st->fd, (struct sockaddr *)&addr, sizeof(addr))!=0) {
	    fatal_perror("udp (%s:%d): bind",st->loc.file,st->loc.line);
	}
    }

    register_for_poll(st,udp_beforepoll,udp_afterpoll,1,"udp");
}

static list_t *udp_apply(closure_t *self, struct cloc loc, dict_t *context,
			 list_t *args)
{
    struct udp *st;
    item_t *i;
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
    st->ops.min_start_pad=0;
    st->ops.min_end_pad=0;
    st->ops.request_notify=request_notify;
    st->ops.release_notify=release_notify;
    st->ops.sendmsg=udp_sendmsg;
    st->port=0;
    st->use_proxy=False;

    i=list_elem(args,0);
    if (!i || i->type!=t_dict) {
	cfgfatal(st->loc,"udp","first argument must be a dictionary\n");
    }
    d=i->data.dict;

    st->port=dict_read_number(d,"port",True,"udp",st->loc,0);
    st->rbuf=find_cl_if(d,"buffer",CL_BUFFER,True,"udp",st->loc);
    st->authbind=dict_read_string(d,"authbind",False,"udp",st->loc);
    l=dict_lookup(d,"proxy");
    if (l) {
	st->use_proxy=True;
	memset(&st->proxy,0,sizeof(st->proxy));
	st->proxy.sin_family=AF_INET;
	i=list_elem(l,0);
	if (!i || i->type!=t_string) {
	    cfgfatal(st->loc,"udp","proxy must supply ""addr"",port\n");
	}
	a=string_item_to_ipaddr(i,"proxy");
	st->proxy.sin_addr.s_addr=htonl(a);
	i=list_elem(l,1);
	if (!i || i->type!=t_number) {
	    cfgfatal(st->loc,"udp","proxy must supply ""addr"",port\n");
	}
	st->proxy.sin_port=htons(i->data.number);
	st->ops.min_start_pad=8;
    }

    add_hook(PHASE_GETRESOURCES,udp_phase_hook,st);

    return new_closure(&st->cl);
}

init_module udp_module;
void udp_module(dict_t *dict)
{
    add_closure(dict,"udp",udp_apply);
}
