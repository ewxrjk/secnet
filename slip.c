/* When dealing with SLIP (to a pty, or ipif) we have separate rx, tx
   and client buffers.  When receiving we may read() any amount, not
   just whole packets.  When transmitting we need to bytestuff anyway,
   and may be part-way through receiving. */

#include "secnet.h"
#include "util.h"
#include "netlink.h"
#include "process.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#define SLIP_END    192
#define SLIP_ESC    219
#define SLIP_ESCEND 220
#define SLIP_ESCESC 221

struct slip {
    struct netlink nl;
    struct buffer_if *buff; /* We unstuff received packets into here
			       and send them to the netlink code. */
    bool_t pending_esc;
    netlink_deliver_fn *netlink_to_tunnel;
    uint32_t local_address;
};

/* Generic SLIP mangling code */

static void slip_stuff(struct slip *st, struct buffer_if *buf, int fd)
{
    uint8_t txbuf[DEFAULT_BUFSIZE];
    uint8_t *i;
    uint32_t j=0;

    BUF_ASSERT_USED(buf);

    /* XXX crunchy bytestuff code */
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
	if ((j+2)>DEFAULT_BUFSIZE) {
	    if (write(fd,txbuf,j)<0) {
		fatal_perror("slip_stuff: write()");
	    }
	    j=0;
	}
    }
    txbuf[j++]=SLIP_END;
    if (write(fd,txbuf,j)<0) {
	fatal_perror("slip_stuff: write()");
    }
    BUF_FREE(buf);
}

static void slip_unstuff(struct slip *st, uint8_t *buf, uint32_t l)
{
    uint32_t i;

    /* XXX really crude unstuff code */
    /* XXX check for buffer overflow */
    BUF_ASSERT_USED(st->buff);
    for (i=0; i<l; i++) {
	if (st->pending_esc) {
	    st->pending_esc=False;
	    switch(buf[i]) {
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
	    switch (buf[i]) {
	    case SLIP_END:
		if (st->buff->size>0) {
		    st->netlink_to_tunnel(&st->nl,st->buff);
		    BUF_ALLOC(st->buff,"userv_afterpoll");
		}
		buffer_init(st->buff,st->nl.max_start_pad);
		break;
	    case SLIP_ESC:
		st->pending_esc=True;
		break;
	    default:
		*(uint8_t *)buf_append(st->buff,1)=buf[i];
		break;
	    }
	}
    }
}

static void slip_init(struct slip *st, struct cloc loc, dict_t *dict,
		      string_t name, netlink_deliver_fn *to_host)
{
    st->netlink_to_tunnel=
	netlink_init(&st->nl,st,loc,dict,
		     "netlink-userv-ipif",NULL,to_host);
    st->buff=find_cl_if(dict,"buffer",CL_BUFFER,True,"name",loc);
    st->local_address=string_item_to_ipaddr(
	dict_find_item(dict,"local-address", True, name, loc),"netlink");
    BUF_ALLOC(st->buff,"slip_init");
    st->pending_esc=False;
}

/* Connection to the kernel through userv-ipif */

struct userv {
    struct slip slip;
    int txfd; /* We transmit to userv */
    int rxfd; /* We receive from userv */
    string_t userv_path;
    string_t service_user;
    string_t service_name;
    pid_t pid;
    bool_t expecting_userv_exit;
};

static int userv_beforepoll(void *sst, struct pollfd *fds, int *nfds_io,
			    int *timeout_io, const struct timeval *tv_now,
			    uint64_t *now)
{
    struct userv *st=sst;

    if (st->rxfd!=-1) {
	*nfds_io=2;
	fds[0].fd=st->txfd;
	fds[0].events=POLLERR; /* Might want to pick up POLLOUT sometime */
	fds[1].fd=st->rxfd;
	fds[1].events=POLLIN|POLLERR|POLLHUP;
    } else {
	*nfds_io=0;
    }
    return 0;
}

static void userv_afterpoll(void *sst, struct pollfd *fds, int nfds,
			    const struct timeval *tv_now, uint64_t *now)
{
    struct userv *st=sst;
    uint8_t rxbuf[DEFAULT_BUFSIZE];
    int l;

    if (nfds==0) return;

    if (fds[1].revents&POLLERR) {
	Message(M_ERR,"%s: userv_afterpoll: POLLERR!\n",st->slip.nl.name);
    }
    if (fds[1].revents&POLLIN) {
	l=read(st->rxfd,rxbuf,DEFAULT_BUFSIZE);
	if (l<0) {
	    if (errno!=EINTR)
		fatal_perror("%s: userv_afterpoll: read(rxfd)",
			     st->slip.nl.name);
	} else if (l==0) {
	    fatal("%s: userv_afterpoll: read(rxfd)=0; userv gone away?\n",
		  st->slip.nl.name);
	} else slip_unstuff(&st->slip,rxbuf,l);
    }
}

/* Send buf to the kernel. Free buf before returning. */
static void userv_deliver_to_kernel(void *sst, struct buffer_if *buf)
{
    struct userv *st=sst;

    slip_stuff(&st->slip,buf,st->txfd);
}

static void userv_userv_callback(void *sst, pid_t pid, int status)
{
    struct userv *st=sst;

    if (pid!=st->pid) {
	Message(M_WARNING,"userv_callback called unexpectedly with pid %d "
		"(expected %d)\n",pid,st->pid);
	return;
    }
    if (!st->expecting_userv_exit) {
	if (WIFEXITED(status)) {
	    fatal("%s: userv exited unexpectedly with status %d\n",
		  st->slip.nl.name,WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
	    fatal("%s: userv exited unexpectedly: uncaught signal %d\n",
		  st->slip.nl.name,WTERMSIG(status));
	} else {
	    fatal("%s: userv stopped unexpectedly\n");
	}
    }
    Message(M_WARNING,"%s: userv subprocess died with status %d\n",
	    st->slip.nl.name,WEXITSTATUS(status));
    st->pid=0;
}

struct userv_entry_rec {
    string_t path;
    char **argv;
    int in;
    int out;
    /* XXX perhaps we should collect and log stderr? */
};

static void userv_entry(void *sst)
{
    struct userv_entry_rec *st=sst;

    dup2(st->in,0);
    dup2(st->out,1);

    /* XXX close all other fds */
    setsid();
    execvp(st->path,st->argv);
    perror("userv-entry: execvp()");
    exit(1);
}

static void userv_invoke_userv(struct userv *st)
{
    struct userv_entry_rec *er;
    int c_stdin[2];
    int c_stdout[2];
    string_t addrs;
    string_t nets;
    string_t s;
    struct netlink_route *r;
    struct ipset *isnets;
    struct subnet_list *snets;
    int i;
    uint8_t confirm;

    if (st->pid) {
	fatal("userv_invoke_userv: already running\n");
    }

    /* This is where we actually invoke userv - all the networks we'll
       be using should already have been registered. */

    addrs=safe_malloc(512,"userv_invoke_userv:addrs");
    snprintf(addrs,512,"%s,%s,%d,slip",
	     ipaddr_to_string(st->slip.local_address),
	     ipaddr_to_string(st->slip.nl.secnet_address),st->slip.nl.mtu);

    r=st->slip.nl.routes;
    isnets=ipset_new();
    for (i=0; i<st->slip.nl.n_routes; i++) {
	if (r[i].up) {
	    struct ipset *sn,*nis;
	    r[i].kup=True;
	    sn=ipset_from_subnet(r[i].net);
	    nis=ipset_union(isnets,sn);
	    ipset_free(sn);
	    ipset_free(isnets);
	    isnets=nis;
	}
    }
    snets=ipset_to_subnet_list(isnets);
    ipset_free(isnets);
    nets=safe_malloc(20*snets->entries,"userv_invoke_userv:nets");
    *nets=0;
    for (i=0; i<snets->entries; i++) {
	s=subnet_to_string(snets->list[i]);
	strcat(nets,s);
	strcat(nets,",");
	free(s);
    }
    nets[strlen(nets)-1]=0;
    subnet_list_free(snets);

    Message(M_INFO,"%s: about to invoke: %s %s %s %s %s\n",st->slip.nl.name,
	    st->userv_path,st->service_user,st->service_name,addrs,nets);

    st->slip.pending_esc=False;

    /* Invoke userv */
    if (pipe(c_stdin)!=0) {
	fatal_perror("userv_invoke_userv: pipe(c_stdin)");
    }
    if (pipe(c_stdout)!=0) {
	fatal_perror("userv_invoke_userv: pipe(c_stdout)");
    }
    st->txfd=c_stdin[1];
    st->rxfd=c_stdout[0];

    er=safe_malloc(sizeof(*r),"userv_invoke_userv: er");

    er->in=c_stdin[0];
    er->out=c_stdout[1];
    /* The arguments are:
       userv
       service-user
       service-name
       local-addr,secnet-addr,mtu,protocol
       route1,route2,... */
    er->argv=safe_malloc(sizeof(*er->argv)*6,"userv_invoke_userv:argv");
    er->argv[0]=st->userv_path;
    er->argv[1]=st->service_user;
    er->argv[2]=st->service_name;
    er->argv[3]=addrs;
    er->argv[4]=nets;
    er->argv[5]=NULL;
    er->path=st->userv_path;

    st->pid=makesubproc(userv_entry, userv_userv_callback,
			er, st, st->slip.nl.name);
    close(er->in);
    close(er->out);
    free(er->argv);
    free(er);
    free(addrs);
    free(nets);
    Message(M_INFO,"%s: userv-ipif pid is %d\n",st->slip.nl.name,st->pid);
    /* Read a single character from the pipe to confirm userv-ipif is
       running. If we get a SIGCHLD at this point then we'll get EINTR. */
    if (read(st->rxfd,&confirm,1)!=1) {
	if (errno==EINTR) {
	    Message(M_WARNING,"%s: read of confirmation byte was "
		    "interrupted\n",st->slip.nl.name);
	} else {
	    fatal_perror("%s: read() of confirmation byte",st->slip.nl.name);
	}
    } else {
	if (confirm!=SLIP_END) {
	    fatal("%s: bad confirmation byte %d from userv-ipif\n",
		  st->slip.nl.name,confirm);
	}
    }
    /* Mark rxfd non-blocking */
    if (fcntl(st->rxfd, F_SETFL, fcntl(st->rxfd, F_GETFL)|O_NONBLOCK)==-1) {
	fatal_perror("%s: fcntl(O_NONBLOCK)",st->slip.nl.name);
    }
}

static void userv_kill_userv(struct userv *st)
{
    if (st->pid) {
	kill(-st->pid,SIGTERM);
	st->expecting_userv_exit=True;
    }
}

static void userv_phase_hook(void *sst, uint32_t newphase)
{
    struct userv *st=sst;
    /* We must wait until signal processing has started before forking
       userv */
    if (newphase==PHASE_RUN) {
	userv_invoke_userv(st);
	/* Register for poll() */
	register_for_poll(st, userv_beforepoll, userv_afterpoll, 2,
			  st->slip.nl.name);
    }
    if (newphase==PHASE_SHUTDOWN) {
	userv_kill_userv(st);
    }
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

    slip_init(&st->slip,loc,dict,"netlink-userv-ipif",
	      userv_deliver_to_kernel);

    st->userv_path=dict_read_string(dict,"userv-path",False,"userv-netlink",
				    loc);
    st->service_user=dict_read_string(dict,"service-user",False,
				      "userv-netlink",loc);
    st->service_name=dict_read_string(dict,"service-name",False,
				      "userv-netlink",loc);
    if (!st->userv_path) st->userv_path="userv";
    if (!st->service_user) st->service_user="root";
    if (!st->service_name) st->service_name="ipif";
    st->rxfd=-1; st->txfd=-1;
    st->pid=0;
    st->expecting_userv_exit=False;
    add_hook(PHASE_RUN,userv_phase_hook,st);
    add_hook(PHASE_SHUTDOWN,userv_phase_hook,st);

    return new_closure(&st->slip.nl.cl);
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
