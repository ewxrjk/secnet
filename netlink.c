/* User-kernel network link */

/* We support a variety of methods: userv-ipif, ipif on its own (when
   we run as root), SLIP to a pty, an external netlink daemon. There
   is a performance/security tradeoff. */

/* When dealing with SLIP (to a pty, or ipif) we have separate rx, tx
   and client buffers. When receiving we may read() any amount, not
   just whole packets. When transmitting we need to bytestuff anyway,
   and may be part-way through receiving. */

/* Each netlink device is actually a router, with its own IP
   address. We should eventually do things like decreasing the TTL and
   recalculating the header checksum, generating ICMP, responding to
   pings, etc. but for now we can get away without them. We should
   implement this stuff no matter how we get the packets to/from the
   kernel. */

/* This is where we have the anti-spoofing paranoia - before sending a
   packet to the kernel we check that the tunnel it came over could
   reasonably have produced it. */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "secnet.h"
#include "util.h"

#define DEFAULT_BUFSIZE 2048

#define SLIP_END    192
#define SLIP_ESC    219
#define SLIP_ESCEND 220
#define SLIP_ESCESC 221

struct netlink_client {
    struct subnet_list *networks;
    netlink_deliver_fn *deliver;
    void *dst;
    struct netlink_client *next;
};

struct userv {
    closure_t cl;
    struct netlink_if ops;
    uint32_t max_start_pad;
    uint32_t max_end_pad;
    int txfd; /* We transmit to userv */
    int rxfd; /* We receive from userv */
    struct netlink_client *clients;
    string_t name;
    string_t userv_path;
    string_t service_user;
    string_t service_name;
    struct subnet_list networks;
    uint32_t local_address;
    uint32_t secnet_address;
    uint32_t mtu;
    uint32_t txbuflen;
    struct buffer_if *buff; /* We unstuff received packets into here
			       and send them to the site code. */
    bool_t pending_esc;
};

static int userv_beforepoll(void *sst, struct pollfd *fds, int *nfds_io,
			    int *timeout_io, const struct timeval *tv_now,
			    uint64_t *now)
{
    struct userv *st=sst;
    *nfds_io=2;
    fds[0].fd=st->txfd;
    fds[0].events=POLLERR; /* Might want to pick up POLLOUT sometime */
    fds[1].fd=st->rxfd;
    fds[1].events=POLLIN|POLLERR|POLLHUP;
    return 0;
}

static void process_local_packet(struct userv *st)
{
    uint32_t source,dest;
    struct netlink_client *c;

    source=ntohl(*(uint32_t *)(st->buff->start+12));
    dest=ntohl(*(uint32_t *)(st->buff->start+16));

/*    printf("process_local_packet source=%s dest=%s len=%d\n",
      ipaddr_to_string(source),ipaddr_to_string(dest),
      st->buff->size); */
    if (!subnet_match(&st->networks,source)) {
	string_t s,d;
	s=ipaddr_to_string(source);
	d=ipaddr_to_string(dest);
	Message(M_WARNING,"%s: outgoing packet with bad source address "
		"(s=%s,d=%s)\n",st->name,s,d);
	free(s); free(d);
	return;
    }
    for (c=st->clients; c; c=c->next) {
	if (subnet_match(c->networks,dest)) {
	    c->deliver(c->dst,c,st->buff);
	    BUF_ALLOC(st->buff,"netlink:process_local_packet");
	    return;
	}
    }
    if (dest==st->secnet_address) {
	printf("%s: secnet received packet of len %d from %s\n",st->name,
	       st->buff->size,ipaddr_to_string(source));
	return;
    }
    {
	string_t s,d;
	s=ipaddr_to_string(source);
	d=ipaddr_to_string(dest);
	Message(M_WARNING,"%s: outgoing packet with bad destination address "
			  "(s=%s,d=%s)\n",st->name,s,d);
	free(s); free(d);
	return;
    }
}

static void userv_afterpoll(void *sst, struct pollfd *fds, int nfds,
			    const struct timeval *tv_now, uint64_t *now)
{
    struct userv *st=sst;
    uint8_t rxbuf[DEFAULT_BUFSIZE];
    int l,i;

    if (fds[1].revents&POLLERR) {
	printf("userv_afterpoll: hup!\n");
    }
    if (fds[1].revents&POLLIN) {
	l=read(st->rxfd,rxbuf,DEFAULT_BUFSIZE);
	if (l<0) {
	    fatal_perror("userv_afterpoll: read(rxfd)");
	}
	if (l==0) {
	    fatal("userv_afterpoll: read(rxfd)=0; userv gone away?\n");
	}
	/* XXX really crude unstuff code */
	/* XXX check for buffer overflow */
	for (i=0; i<l; i++) {
	    if (st->pending_esc) {
		st->pending_esc=False;
		switch(rxbuf[i]) {
		case SLIP_ESCEND:
		    *(uint8_t *)buf_append(st->buff,1)=SLIP_END;
		    break;
		case SLIP_ESCESC:
		    *(uint8_t *)buf_append(st->buff,1)=SLIP_ESC;
		    break;
		default:
		    fatal("userv_afterpoll: bad SLIP escape character\n");
		}
	    } else {
		switch (rxbuf[i]) {
		case SLIP_END:
		    if (st->buff->size>0) process_local_packet(st);
		    BUF_ASSERT_USED(st->buff);
		    buffer_init(st->buff,st->max_start_pad);
		    break;
		case SLIP_ESC:
		    st->pending_esc=True;
		    break;
		default:
		    *(uint8_t *)buf_append(st->buff,1)=rxbuf[i];
		    break;
		}
	    }
	}
    }
    return;
}

static void userv_phase_hook(void *sst, uint32_t newphase)
{
    struct userv *st=sst;
    pid_t child;
    int c_stdin[2];
    int c_stdout[2];
    string_t addrs;
    string_t nets;
    string_t s;
    struct netlink_client *c;
    int i;

    /* This is where we actually invoke userv - all the networks we'll
       be using should already have been registered. */

    addrs=safe_malloc(512,"userv_phase_hook:addrs");
    snprintf(addrs,512,"%s,%s,%d,slip",ipaddr_to_string(st->local_address),
	     ipaddr_to_string(st->secnet_address),st->mtu);

    nets=safe_malloc(1024,"userv_phase_hook:nets");
    *nets=0;
    for (c=st->clients; c; c=c->next) {
	for (i=0; i<c->networks->entries; i++) {
	    s=subnet_to_string(&c->networks->list[i]);
	    strcat(nets,s);
	    strcat(nets,",");
	    free(s);
	}
    }
    nets[strlen(nets)-1]=0;

    Message(M_INFO,"\nuserv_phase_hook: %s %s %s %s %s\n",st->userv_path,
	   st->service_user,st->service_name,addrs,nets);

    /* Allocate buffer, plus space for padding. Make sure we end up
       with the start of the packet well-aligned. */
    /* ALIGN(st->max_start_pad,16); */
    /* ALIGN(st->max_end_pad,16); */

    st->pending_esc=False;

    /* Invoke userv */
    if (pipe(c_stdin)!=0) {
	fatal_perror("userv_phase_hook: pipe(c_stdin)");
    }
    if (pipe(c_stdout)!=0) {
	fatal_perror("userv_phase_hook: pipe(c_stdout)");
    }
    st->txfd=c_stdin[1];
    st->rxfd=c_stdout[0];

    child=fork();
    if (child==-1) {
	fatal_perror("userv_phase_hook: fork()");
    }
    if (child==0) {
	char **argv;

	/* We are the child. Modify our stdin and stdout, then exec userv */
	dup2(c_stdin[0],0);
	dup2(c_stdout[1],1);
	close(c_stdin[1]);
	close(c_stdout[0]);

	/* The arguments are:
	   userv
	   service-user
	   service-name
	   local-addr,secnet-addr,mtu,protocol
	   route1,route2,... */
	argv=malloc(sizeof(*argv)*6);
	argv[0]=st->userv_path;
	argv[1]=st->service_user;
	argv[2]=st->service_name;
	argv[3]=addrs;
	argv[4]=nets;
	argv[5]=NULL;
	execvp(st->userv_path,argv);
	perror("netlink-userv-ipif: execvp");

	exit(1);
    }
    /* We are the parent... */
	   
    /* Register for poll() */
    register_for_poll(st, userv_beforepoll, userv_afterpoll, 2, "netlink");
}

static void *userv_regnets(void *sst, struct subnet_list *nets,
			   netlink_deliver_fn *deliver, void *dst,
			   uint32_t max_start_pad, uint32_t max_end_pad)
{
    struct userv *st=sst;
    struct netlink_client *c;

    Message(M_DEBUG_CONFIG,"userv_regnets: request for %d networks, "
	    "max_start_pad=%d, max_end_pad=%d\n",
	    nets->entries,max_start_pad,max_end_pad);

    c=safe_malloc(sizeof(*c),"userv_regnets");
    c->networks=nets;
    c->deliver=deliver;
    c->dst=dst;
    c->next=st->clients;
    st->clients=c;
    if (max_start_pad > st->max_start_pad) st->max_start_pad=max_start_pad;
    if (max_end_pad > st->max_end_pad) st->max_end_pad=max_end_pad;

    return c;
}

static void userv_deliver(void *sst, void *cid, struct buffer_if *buf)
{
    struct userv *st=sst;
    struct netlink_client *client=cid;
    uint8_t txbuf[DEFAULT_BUFSIZE];

    uint32_t source,dest;
    uint8_t *i;
    uint32_t j;

    source=ntohl(*(uint32_t *)(buf->start+12));
    dest=ntohl(*(uint32_t *)(buf->start+16));

    /* Check that the packet source is in 'nets' and its destination is
       in client->networks */
    if (!subnet_match(client->networks,source)) {
	string_t s,d;
	s=ipaddr_to_string(source);
	d=ipaddr_to_string(dest);
	Message(M_WARNING,"%s: incoming packet with bad source address "
		"(s=%s,d=%s)\n",st->name,s,d);
	free(s); free(d);
	return;
    }
    if (!subnet_match(&st->networks,dest)) {
	string_t s,d;
	s=ipaddr_to_string(source);
	d=ipaddr_to_string(dest);
	Message(M_WARNING,"%s: incoming packet with bad destination address "
		"(s=%s,d=%s)\n",st->name,s,d);
	free(s); free(d);
	return;
    }

    /* Really we should decrease TTL, check it's above zero, and
       recalculate header checksum here. If it gets down to zero,
       generate an ICMP time-exceeded and send the new packet back to
       the originating tunnel. XXX check buffer usage! */

    /* (Basically do full IP packet forwarding stuff. Except that we
       know any packet passed in here is destined for the local
       machine; only exception is if it's destined for us.) */

    if (dest==st->secnet_address) {
	printf("%s: incoming tunneled packet for secnet!\n",st->name);
	return;
    }

    /* Now spit the packet at userv-ipif: SLIP start marker, then
       bytestuff the packet, then SLIP end marker */
    /* XXX crunchy bytestuff code */
    j=0;
    txbuf[j++]=SLIP_END;
    for (i=buf->start; i<(buf->start+buf->size); i++) {
	switch (*i) {
	case SLIP_END:
	    txbuf[j++]=SLIP_ESC;
	    txbuf[j++]=SLIP_ESCEND;
	    break;
	case SLIP_ESC:
	    txbuf[j++]=SLIP_ESC;
	    txbuf[j++]=SLIP_ESCESC;
	    break;
	default:
	    txbuf[j++]=*i;
	    break;
	}
    }
    txbuf[j++]=SLIP_END;
    if (write(st->txfd,txbuf,j)<0) {
	fatal_perror("userv_deliver: write()");
    }

    return;
}

static list_t *userv_apply(closure_t *self, struct cloc loc, dict_t *context,
			   list_t *args)
{
    struct userv *st;
    item_t *item;
    dict_t *dict;

    st=safe_malloc(sizeof(*st),"userv_apply (netlink)");
    st->cl.description="userv-netlink";
    st->cl.type=CL_NETLINK;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.regnets=userv_regnets;
    st->ops.deliver=userv_deliver;
    st->max_start_pad=0;
    st->max_end_pad=0;
    st->rxfd=-1; st->txfd=-1;
    st->clients=NULL;

    /* First parameter must be a dict */
    item=list_elem(args,0);
    if (!item || item->type!=t_dict)
	cfgfatal(loc,"userv-ipif","parameter must be a dictionary\n");
    
    dict=item->data.dict;
    st->name=dict_read_string(dict,"name",False,"userv-netlink",loc);
    st->userv_path=dict_read_string(dict,"userv-path",False,"userv-netlink",
				    loc);
    st->service_user=dict_read_string(dict,"service-user",False,
				      "userv-netlink",loc);
    st->service_name=dict_read_string(dict,"service-name",False,
				      "userv-netlink",loc);
    if (!st->name) st->name="netlink-userv-ipif";
    if (!st->userv_path) st->userv_path="userv";
    if (!st->service_user) st->service_user="root";
    if (!st->service_name) st->service_name="ipif";
    dict_read_subnet_list(dict, "networks", True, "userv-netlink", loc,
			  &st->networks);
    st->local_address=string_to_ipaddr(
	dict_find_item(dict,"local-address", True, "userv-netlink", loc),
	"userv-netlink");
    st->secnet_address=string_to_ipaddr(
	dict_find_item(dict,"secnet-address", True, "userv-netlink", loc),
	"userv-netlink");
    if (!subnet_match(&st->networks,st->local_address)) {
	cfgfatal(loc,"netlink-userv-ipif","local-address must be in "
	      "local networks\n");
    }
    st->mtu=dict_read_number(dict, "mtu", False, "userv-netlink", loc, 1000);
    st->buff=find_cl_if(dict,"buffer",CL_BUFFER,True,"userv-netlink",loc);
    BUF_ALLOC(st->buff,"netlink:userv_apply");

    add_hook(PHASE_DROPPRIV,userv_phase_hook,st);

    return new_closure(&st->cl);
}

struct null {
    closure_t cl;
    struct netlink_if ops;
};

static void *null_regnets(void *sst, struct subnet_list *nets,
			  netlink_deliver_fn *deliver, void *dst,
			  uint32_t max_start_pad, uint32_t max_end_pad)
{
    Message(M_DEBUG_CONFIG,"null_regnets: request for %d networks, "
	    "max_start_pad=%d, max_end_pad=%d\n",
	    nets->entries,max_start_pad,max_end_pad);
    return NULL;
}

static void null_deliver(void *sst, void *cid, struct buffer_if *buf)
{
    return;
}

static list_t *null_apply(closure_t *self, struct cloc loc, dict_t *context,
			  list_t *args)
{
    struct null *st;

    st=safe_malloc(sizeof(*st),"null_apply (netlink)");
    st->cl.description="null-netlink";
    st->cl.type=CL_NETLINK;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.regnets=null_regnets;
    st->ops.deliver=null_deliver;

    return new_closure(&st->cl);
}

init_module netlink_module;
void netlink_module(dict_t *dict)
{
    add_closure(dict,"userv-ipif",userv_apply);
#if 0
    add_closure(dict,"pty-slip",ptyslip_apply);
    add_closure(dict,"slipd",slipd_apply);
#endif /* 0 */
    add_closure(dict,"null-netlink",null_apply);
}
