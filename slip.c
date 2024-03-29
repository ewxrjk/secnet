/* When dealing with SLIP (to a pty, or ipif) we have separate rx, tx
   and client buffers.  When receiving we may read() any amount, not
   just whole packets.  When transmitting we need to bytestuff anyway,
   and may be part-way through receiving. */

/*
 * This file is part of secnet.
 * See README for full list of copyright holders.
 *
 * secnet is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
#include "netlink.h"
#include "process.h"
#include "unaligned.h"
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
    bool_t ignoring_packet; /* If this packet was corrupt or overlong,
			       we ignore everything up to the next END */
    netlink_deliver_fn *netlink_to_tunnel;
};

/* Generic SLIP mangling code */

static void slip_write(int fd, const uint8_t *p, size_t l)
{
    while (l) {
	ssize_t written=write(fd,p,l);
	if (written<0) {
	    if (errno==EINTR) {
		continue;
	    } else if (iswouldblock(errno)) {
		lg_perror(0,"slip",0,M_ERR,errno,"write() (packet(s) lost)");
		return;
	    } else {
		fatal_perror("slip_stuff: write()");
	    }
	}
	assert(written>0);
	assert((size_t)written<=l);
	p+=written;
	l-=written;
    }
}

static void slip_stuff(struct slip *st, struct buffer_if *buf, int fd)
{
    uint8_t txbuf[DEFAULT_BUFSIZE];
    uint8_t *i;
    int32_t j=0;

    BUF_ASSERT_USED(buf);

    /* There's probably a much more efficient way of implementing this */
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
	    slip_write(fd,txbuf,j);
	    j=0;
	}
    }
    txbuf[j++]=SLIP_END;
    slip_write(fd,txbuf,j);
    BUF_FREE(buf);
}

static void slip_unstuff(struct slip *st, uint8_t *buf, uint32_t l)
{
    uint32_t i;

    BUF_ASSERT_USED(st->buff);
    for (i=0; i<l; i++) {
	int outputchr;
	enum { OUTPUT_END = 256, OUTPUT_NOTHING = 257 };

	if (!st->buff->size)
	    buffer_init(st->buff,calculate_max_start_pad());

	if (st->pending_esc) {
	    st->pending_esc=False;
	    switch(buf[i]) {
	    case SLIP_ESCEND:
		outputchr=SLIP_END;
		break;
	    case SLIP_ESCESC:
		outputchr=SLIP_ESC;
		break;
	    default:
		if (!st->ignoring_packet) {
		    Message(M_WARNING, "userv_afterpoll: bad SLIP escape"
			    " character, dropping packet\n");
		}
		st->ignoring_packet=True;
		outputchr=OUTPUT_NOTHING;
		break;
	    }
	} else {
	    switch (buf[i]) {
	    case SLIP_END:
		outputchr=OUTPUT_END;
		break;
	    case SLIP_ESC:
		st->pending_esc=True;
		outputchr=OUTPUT_NOTHING;
		break;
	    default:
		outputchr=buf[i];
		break;
	    }
	}

	if (st->ignoring_packet) {
	    if (outputchr == OUTPUT_END) {
		st->ignoring_packet=False;
		st->buff->size=0;
	    }
	} else {
	    if (outputchr == OUTPUT_END) {
		if (st->buff->size>0) {
		    st->netlink_to_tunnel(&st->nl,st->buff);
		    BUF_ALLOC(st->buff,"userv_afterpoll");
		}
		st->buff->size=0;
	    } else if (outputchr != OUTPUT_NOTHING) {
		if (buf_remaining_space(st->buff)) {
		    buf_append_uint8(st->buff,outputchr);
		} else {
		    Message(M_WARNING, "userv_afterpoll: dropping overlong"
			    " SLIP packet\n");
		    st->ignoring_packet=True;
		}
	    }
	}
    }
}

static void slip_init(struct slip *st, struct cloc loc, dict_t *dict,
		      cstring_t name, netlink_deliver_fn *to_host)
{
    st->netlink_to_tunnel=
	netlink_init(&st->nl,st,loc,dict,
		     "netlink-userv-ipif",NULL,to_host);
    st->buff=find_cl_if(dict,"buffer",CL_BUFFER,True,"name",loc);
    BUF_ALLOC(st->buff,"slip_init");
    st->pending_esc=False;
    st->ignoring_packet=False;
}

/* Connection to the kernel through userv-ipif */

struct userv {
    struct slip slip;
    int txfd; /* We transmit to userv */
    int rxfd; /* We receive from userv */
    cstring_t userv_path;
    cstring_t service_user;
    cstring_t service_name;
    pid_t pid;
    bool_t expecting_userv_exit;
};

static int userv_beforepoll(void *sst, struct pollfd *fds, int *nfds_io,
			    int *timeout_io)
{
    struct userv *st=sst;

    if (st->rxfd!=-1) {
	BEFOREPOLL_WANT_FDS(2);
	fds[0].fd=st->txfd;
	fds[0].events=0; /* Might want to pick up POLLOUT sometime */
	fds[1].fd=st->rxfd;
	fds[1].events=POLLIN;
    } else {
	BEFOREPOLL_WANT_FDS(0);
    }
    return 0;
}

static void userv_afterpoll(void *sst, struct pollfd *fds, int nfds)
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
	    if (errno!=EINTR && !iswouldblock(errno))
		fatal_perror("%s: userv_afterpoll: read(rxfd)",
			     st->slip.nl.name);
	} else if (l==0) {
	    fatal("%s: userv_afterpoll: read(rxfd)=0; userv gone away?",
		  st->slip.nl.name);
	} else slip_unstuff(&st->slip,rxbuf,l);
    }
}

/* Send buf to the kernel. Free buf before returning. */
static void userv_deliver_to_kernel(void *sst, struct buffer_if *buf)
{
    struct userv *st=sst;

    if (buf->size > st->slip.nl.mtu) {
	Message(M_ERR,"%s: packet of size %"PRIu32" exceeds mtu %"PRIu32":"
		" cannot be injected into kernel, dropped\n",
		st->slip.nl.name, buf->size, st->slip.nl.mtu);
	BUF_FREE(buf);
	return;
    }

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
    if (!(st->expecting_userv_exit &&
	  (!status ||
	   (WIFSIGNALED(status) && WTERMSIG(status)==SIGTERM)))) {
	lg_exitstatus(0,st->slip.nl.name,0,
		      st->expecting_userv_exit ? M_WARNING : M_FATAL,
		      status,"userv");
    }
    st->pid=0;
}

struct userv_entry_rec {
    cstring_t path;
    const char **argv;
    int in;
    int out;
    /* XXX perhaps we should collect and log stderr? */
};

static void userv_entry(void *sst)
{
    struct userv_entry_rec *st=sst;

    dup2(st->in,0);
    dup2(st->out,1);

    setsid();
    execvp(st->path,(char *const*)st->argv);
    perror("userv-entry: execvp()");
    exit(1);
}

static void userv_invoke_userv(struct userv *st)
{
    struct userv_entry_rec er[1];
    int c_stdin[2];
    int c_stdout[2];
    string_t nets;
    string_t s;
    struct netlink_client *r;
    struct ipset *allnets;
    struct subnet_list *snets;
    int i, nread;
    uint8_t confirm;

    if (st->pid) {
	fatal("userv_invoke_userv: already running");
    }

    /* This is where we actually invoke userv - all the networks we'll
       be using should already have been registered. */

    char addrs[512];
    snprintf(addrs,sizeof(addrs),"%s,%s,%d,slip",
	     ipaddr_to_string(st->slip.nl.local_address),
	     ipaddr_to_string(st->slip.nl.secnet_address),st->slip.nl.mtu);

    allnets=ipset_new();
    for (r=st->slip.nl.clients; r; r=r->next) {
	if (r->link_quality > LINK_QUALITY_UNUSED) {
	    struct ipset *nan;
	    r->kup=True;
	    nan=ipset_union(allnets,r->networks);
	    ipset_free(allnets);
	    allnets=nan;
	}
    }
    snets=ipset_to_subnet_list(allnets);
    ipset_free(allnets);
    nets=safe_malloc(20*snets->entries,"userv_invoke_userv:nets");
    *nets=0;
    for (i=0; i<snets->entries; i++) {
	s=subnet_to_string(snets->list[i]);
	strcat(nets,s);
	strcat(nets,",");
    }
    nets[strlen(nets)-1]=0;
    subnet_list_free(snets);

    Message(M_INFO,"%s: about to invoke: %s %s %s %s %s\n",st->slip.nl.name,
	    st->userv_path,st->service_user,st->service_name,addrs,nets);

    st->slip.pending_esc=False;

    /* Invoke userv */
    pipe_cloexec(c_stdin);
    pipe_cloexec(c_stdout);
    st->txfd=c_stdin[1];
    st->rxfd=c_stdout[0];

    er->in=c_stdin[0];
    er->out=c_stdout[1];
    /* The arguments are:
       userv
       service-user
       service-name
       local-addr,secnet-addr,mtu,protocol
       route1,route2,... */
    const char *er_argv[6];
    er->argv=er_argv;
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
    free(nets);
    Message(M_INFO,"%s: userv-ipif pid is %d\n",st->slip.nl.name,st->pid);
    /* Read a single character from the pipe to confirm userv-ipif is
       running. If we get a SIGCHLD at this point then we'll get EINTR. */
    if ((nread=read(st->rxfd,&confirm,1))!=1) {
	if (errno==EINTR) {
	    Message(M_WARNING,"%s: read of confirmation byte was "
		    "interrupted\n",st->slip.nl.name);
	} else {
	    if (nread<0) {
		fatal_perror("%s: error reading confirmation byte",
			     st->slip.nl.name);
	    } else {
		fatal("%s: unexpected EOF instead of confirmation byte"
		      " - userv ipif failed?", st->slip.nl.name);
	    }
	}
    } else {
	if (confirm!=SLIP_END) {
	    fatal("%s: bad confirmation byte %d from userv-ipif",
		  st->slip.nl.name,confirm);
	}
    }
    setnonblock(st->txfd);
    setnonblock(st->rxfd);

    add_hook(PHASE_CHILDPERSIST,childpersist_closefd_hook,&st->txfd);
    add_hook(PHASE_CHILDPERSIST,childpersist_closefd_hook,&st->rxfd);
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
	register_for_poll(st, userv_beforepoll, userv_afterpoll,
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

    NEW(st);

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

void slip_module(dict_t *dict)
{
    add_closure(dict,"userv-ipif",userv_apply);
}
