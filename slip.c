/* When dealing with SLIP (to a pty, or ipif) we have separate rx, tx
   and client buffers.  When receiving we may read() any amount, not
   just whole packets.  When transmitting we need to bytestuff anyway,
   and may be part-way through receiving. */

#include "secnet.h"
#include "util.h"
#include "netlink.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SLIP_END    192
#define SLIP_ESC    219
#define SLIP_ESCEND 220
#define SLIP_ESCESC 221

/* Connection to the kernel through userv-ipif */

struct userv {
    struct netlink nl;
    int txfd; /* We transmit to userv */
    int rxfd; /* We receive from userv */
    string_t userv_path;
    string_t service_user;
    string_t service_name;
    uint32_t txbuflen;
    struct buffer_if *buff; /* We unstuff received packets into here
			       and send them to the site code. */
    bool_t pending_esc;
    netlink_deliver_fn *netlink_to_tunnel;
    uint32_t local_address; /* host interface address */
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

static void userv_afterpoll(void *sst, struct pollfd *fds, int nfds,
			    const struct timeval *tv_now, uint64_t *now)
{
    struct userv *st=sst;
    uint8_t rxbuf[DEFAULT_BUFSIZE];
    int l,i;

    if (fds[1].revents&POLLERR) {
	Message(M_ERROR,"%s: userv_afterpoll: hup!\n",st->nl.name);
    }
    if (fds[1].revents&POLLIN) {
	l=read(st->rxfd,rxbuf,DEFAULT_BUFSIZE);
	if (l<0) {
	    fatal_perror("%s: userv_afterpoll: read(rxfd)",st->nl.name);
	}
	if (l==0) {
	    fatal("%s: userv_afterpoll: read(rxfd)=0; userv gone away?\n",
		  st->nl.name);
	}
	/* XXX really crude unstuff code */
	/* XXX check for buffer overflow */
	BUF_ASSERT_USED(st->buff);
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
		    if (st->buff->size>0) {
			st->netlink_to_tunnel(&st->nl,NULL,
					      st->buff);
			BUF_ALLOC(st->buff,"userv_afterpoll");
		    }
		    buffer_init(st->buff,st->nl.max_start_pad);
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
}

/* Send buf to the kernel. Free buf before returning. */
static void userv_deliver_to_kernel(void *sst, void *cid,
				    struct buffer_if *buf)
{
    struct userv *st=sst;
    uint8_t txbuf[DEFAULT_BUFSIZE];
    uint8_t *i;
    uint32_t j;

    BUF_ASSERT_USED(buf);

    /* Spit the packet at userv-ipif: SLIP start marker, then
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
	fatal_perror("userv_deliver_to_kernel: write()");
    }
    BUF_FREE(buf);
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
    struct netlink_route *r;
    int i;

    /* This is where we actually invoke userv - all the networks we'll
       be using should already have been registered. */

    addrs=safe_malloc(512,"userv_phase_hook:addrs");
    snprintf(addrs,512,"%s,%s,%d,slip",ipaddr_to_string(st->local_address),
	     ipaddr_to_string(st->nl.secnet_address),st->nl.mtu);

    nets=safe_malloc(1024,"userv_phase_hook:nets");
    *nets=0;
    r=st->nl.routes;
    for (i=0; i<st->nl.n_routes; i++) {
	if (r[i].up) {
	    r[i].kup=True;
	    s=subnet_to_string(&r[i].net);
	    strcat(nets,s);
	    strcat(nets,",");
	    free(s);
	}
    }
    nets[strlen(nets)-1]=0;

    Message(M_INFO,"%s: about to invoke: %s %s %s %s %s\n",st->nl.name,
	    st->userv_path,st->service_user,st->service_name,addrs,nets);

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
    register_for_poll(st, userv_beforepoll, userv_afterpoll, 2, st->nl.name);
}

static list_t *userv_apply(closure_t *self, struct cloc loc, dict_t *context,
			   list_t *args)
{
    struct userv *st;
    item_t *item;
    dict_t *dict;

    st=safe_malloc(sizeof(*st),"userv_apply");

    /* First parameter must be a dict */
    item=list_elem(args,0);
    if (!item || item->type!=t_dict)
	cfgfatal(loc,"userv-ipif","parameter must be a dictionary\n");
    
    dict=item->data.dict;

    st->netlink_to_tunnel=
	netlink_init(&st->nl,st,loc,dict,
		     "netlink-userv-ipif",NULL,userv_deliver_to_kernel);

    st->userv_path=dict_read_string(dict,"userv-path",False,"userv-netlink",
				    loc);
    st->service_user=dict_read_string(dict,"service-user",False,
				      "userv-netlink",loc);
    st->service_name=dict_read_string(dict,"service-name",False,
				      "userv-netlink",loc);
    if (!st->userv_path) st->userv_path="userv";
    if (!st->service_user) st->service_user="root";
    if (!st->service_name) st->service_name="ipif";
    st->buff=find_cl_if(dict,"buffer",CL_BUFFER,True,"userv-netlink",loc);
    st->local_address=string_to_ipaddr(
	dict_find_item(dict,"local-address", True, "netlink", loc),"netlink");
    BUF_ALLOC(st->buff,"netlink:userv_apply");

    st->rxfd=-1; st->txfd=-1;
    add_hook(PHASE_DROPPRIV,userv_phase_hook,st);

    return new_closure(&st->nl.cl);
}

init_module slip_module;
void slip_module(dict_t *dict)
{
    add_closure(dict,"userv-ipif",userv_apply);
#if 0
    /* TODO */
    add_closure(dict,"pty-slip",ptyslip_apply);
    add_closure(dict,"slipd",slipd_apply);
#endif /* 0 */
}
