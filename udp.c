/* UDP send/receive module for secnet */

/* This module enables sites to communicate by sending UDP
 * packets. When an instance of the module is created we can
 * optionally bind to a particular local IP address (not implemented
 * yet).
 *
 * Sites register an interest in local port numbers for receiving
 * packets, and can also send packets. We don't care about the source
 * port number for sending packets. 
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
#include "util.h"

static beforepoll_fn udp_beforepoll;
static afterpoll_fn udp_afterpoll;
static comm_request_notify_fn request_notify;
static comm_release_notify_fn release_notify;
static comm_sendmsg_fn udp_sendmsg;

/* The UDP module exports a pure closure which can be used to construct a
 * UDP send/receive module. Arguments:
 */

struct notify_list {
    comm_notify_fn *fn;
    void *state;
    struct notify_list *next;
};

struct udp {
    closure_t cl;
    struct comm_if ops;
    struct cloc loc;
    int fd;
    struct buffer_if *rbuf;
    struct notify_list *notify;
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
		done=False;
		for (n=st->notify; n; n=n->next) {
		    if (n->fn(n->state, st->rbuf, &from)) {
			done=True;
			break;
		    }
		}
		if (!done) {
		    /* XXX manufacture and send NAK packet */
		    Message(M_WARNING,"Need to send NAK\n");
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

    /* XXX fix error reporting */
    sendto(st->fd, buf->start, buf->size, 0,
	   (struct sockaddr *)dest, sizeof(*dest));

    return True;
}

static list_t *udp_apply(closure_t *self, struct cloc loc, dict_t *context,
			 list_t *args)
{
    struct udp *st;
    item_t *i;
    dict_t *d;
    uint16_t local_port=0;
    struct sockaddr_in addr;

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

    i=list_elem(args,0);
    if (!i || i->type!=t_dict) {
	cfgfatal(st->loc,"udp","first argument must be a dictionary\n");
    }
    d=i->data.dict;

    local_port=dict_read_number(d,"port",False,"udp",st->loc,0);
    st->rbuf=find_cl_if(d,"buffer",CL_BUFFER,True,"udp",st->loc);

    st->fd=socket(AF_INET, SOCK_DGRAM, 0);
    if (st->fd<0) {
	fatal_perror("udp_apply (%s:%d): socket",loc.file,loc.line);
    }
    if (fcntl(st->fd, F_SETFL, fcntl(st->fd, F_GETFL)|O_NONBLOCK)==-1) {
	fatal_perror("udp_apply (%s:%d): fcntl(set O_NONBLOCK)",
		     loc.file,loc.line);
    }
    if (fcntl(st->fd, F_SETFD, FD_CLOEXEC)==-1) {
	fatal_perror("udp_apply (%s:%d): fcntl(set FD_CLOEXEC)",
		     loc.file,loc.line);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family=AF_INET;
    if (local_port) {
	addr.sin_port=htons(local_port);
    }
    if (bind(st->fd, (struct sockaddr *)&addr, sizeof(addr))!=0) {
	fatal_perror("udp_apply (%s:%d): bind",loc.file,loc.line);
    }

    register_for_poll(st,udp_beforepoll,udp_afterpoll,1,"udp");

    return new_closure(&st->cl);
}

init_module udp_module;
void udp_module(dict_t *dict)
{
    add_closure(dict,"udp",udp_apply);
}
