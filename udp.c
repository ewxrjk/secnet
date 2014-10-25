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
#include "comm-common.h"

static comm_sendmsg_fn udp_sendmsg;

struct udp {
    struct udpcommon uc;
    struct udpsocks socks;
    bool_t addr_configured;
    unsigned counter;
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

static const char *udp_addr_to_string(void *commst, const struct comm_addr *ca)
{
    struct udp *st=commst;
    struct udpsocks *socks=&st->socks;
    static char sbuf[100];
    int ix=ca->ix>=0 ? ca->ix : 0;

    assert(ix>=0 && ix<socks->n_socks);
    snprintf(sbuf, sizeof(sbuf), "udp#%u@l%d:%s%s-%s",
	     st->counter, st->uc.cc.loc.line,
	     iaddr_to_string(&socks->socks[ix].addr),
	     ca->ix<0 && socks->n_socks>1 ? "&" : "",
	     iaddr_to_string(&ca->ia));
    return sbuf;
}

static int udp_socks_beforepoll(void *state, struct pollfd *fds, int *nfds_io,
				int *timeout_io)
{
    struct udpsocks *socks=state;
    int i;
    BEFOREPOLL_WANT_FDS(socks->n_socks);
    for (i=0; i<socks->n_socks; i++) {
	fds[i].fd=socks->socks[i].fd;
	fds[i].events=POLLIN;
    }
    return 0;
}

const char *af_name(int af)
{
    switch (af) {
    case AF_INET6: return "IPv6";
    case AF_INET:  return "IPv4";
    case 0:        return "(any)";
    default: abort();
    }
}

void udp_sock_experienced(struct log_if *lg, struct udpcommon *uc,
			  struct udpsocks *socks, struct udpsock *us,
			  const union iaddr *dest, int af,
			  int r, int errnoval)
{
    bool_t success=r>=0;
    if (us->experienced[!!dest][af][success]++)
	return;
    lg_perror(lg, uc->cc.cl.description, &uc->cc.loc,
	      success ? M_INFO : M_WARNING,
	      success ? 0 : errnoval,
	      "%s %s experiencing some %s %s%s%s%s%s%s",
	      socks->desc,iaddr_to_string(&us->addr),
	      success?"success":"trouble",
	      dest?"transmitting":"receiving",
	      af?" ":"", af?af_name(af):"",
	      dest?" (to ":"",
	      dest?iaddr_to_string(dest):"",
	      dest?")":"");
}

static void udp_socks_afterpoll(void *state, struct pollfd *fds, int nfds)
{
    struct udpsocks *socks=state;
    struct udpcommon *uc=socks->uc;
    union iaddr from;
    socklen_t fromlen;
    bool_t done;
    int rv;
    int i;

    struct commcommon *cc=&uc->cc;

    for (i=0; i<socks->n_socks; i++) {
	struct udpsock *us=&socks->socks[i];
	if (i>=nfds) continue;
	if (!(fds[i].revents & POLLIN)) continue;
	assert(fds[i].fd == us->fd);
	int fd=us->fd;
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
		    if (!iaddr_equal(&from,&uc->proxy,False)) {
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
		done=comm_notify(&cc->notify, cc->rbuf, &ca);
		if (done) {
		    udp_sock_experienced(0,uc,socks,us,0,
					 from.sa.sa_family,0,0);
		} else {
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
	    } else { /* rv<=0 */
		if (errno!=EINTR && !iswouldblock(errno))
		    udp_sock_experienced(0,uc,socks,us, 0,0, rv,errno);
		BUF_FREE(cc->rbuf);
	    }
	} while (rv>=0);
    }
}

static bool_t udp_sendmsg(void *commst, struct buffer_if *buf,
			  const struct comm_addr *dest)
{
    struct udp *st=commst;
    struct udpcommon *uc=&st->uc;
    struct udpsocks *socks=&st->socks;
    uint8_t *sa;

    if (uc->use_proxy) {
	struct udpsock *us=&socks->socks[0];
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
	int r=sendto(us->fd,sa,buf->size+8,0,&uc->proxy.sa,
	       iaddr_socklen(&uc->proxy));
	udp_sock_experienced(0,uc,socks,us, &dest->ia,0, r,errno);
	buf_unprepend(buf,8);
    } else {
	int i,r;
	bool_t allunsupported=True;
	int af=dest->ia.sa.sa_family;
	for (i=0; i<socks->n_socks; i++) {
	    struct udpsock *us=&socks->socks[i];
	    if (us->addr.sa.sa_family != af)
		/* no point even trying */
		continue;
	    r=sendto(us->fd, buf->start, buf->size, 0,
		     &dest->ia.sa, iaddr_socklen(&dest->ia));
	    udp_sock_experienced(0,uc,socks,us, &dest->ia,af, r,errno);
	    if (r>=0) return True;
	    if (!(errno==EAFNOSUPPORT || errno==ENETUNREACH))
		/* who knows what that error means? */
		allunsupported=False;
	}
	return !allunsupported; /* see doc for comm_sendmsg_fn in secnet.h */
    }

    return True;
}

void udp_destroy_socket(struct udpcommon *uc, struct udpsock *us)
{
    if (us->fd>=0) {
	close(us->fd);
	us->fd=-1;
    }
}

#define FAIL_LG 0, cc->cl.description, &cc->loc, failmsgclass
#define FAIL(...) do{						\
        lg_perror(FAIL_LG,errno,__VA_ARGS__);	\
	goto failed;						\
    }while(0)

static bool_t record_socket_gotaddr(struct udpcommon *uc, struct udpsock *us,
				    int failmsgclass)
{
    struct commcommon *cc=&uc->cc;
    socklen_t salen=sizeof(us->addr);
    int r=getsockname(us->fd,&us->addr.sa,&salen);
    if (r) FAIL("getsockname()");
    if (salen>sizeof(us->addr)) { errno=0; FAIL("getsockname() length"); }
    return True;

 failed:
    return False;
}

bool_t udp_import_socket(struct udpcommon *uc, struct udpsock *us,
			 int failmsgclass, int fd)
{
    FILLZERO(us->experienced);
    us->fd=fd;
    return record_socket_gotaddr(uc,us,failmsgclass);
}

bool_t udp_make_socket(struct udpcommon *uc, struct udpsock *us,
		       int failmsgclass)
{
    const union iaddr *addr=&us->addr;
    struct commcommon *cc=&uc->cc;
    us->fd=-1;

    FILLZERO(us->experienced);
    us->fd=socket(addr->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (us->fd<0) FAIL("socket");
    setnonblock(us->fd);
    setcloexec(us->fd);
#ifdef CONFIG_IPV6
    if (addr->sa.sa_family==AF_INET6) {
	int r;
	int optval=1;
	socklen_t optlen=sizeof(optval);
	r=setsockopt(us->fd,IPPROTO_IPV6,IPV6_V6ONLY,&optval,optlen);
	if (r) FAIL("setsockopt(,IPV6_V6ONLY,&1,)");
    }
#endif

    if (uc->authbind) {
	pid_t c;
	int status;
	char desc[200];
	snprintf(desc,sizeof(desc),"authbind for %s: %s",
		 iaddr_to_string(addr), uc->authbind);

	/* XXX this fork() and waitpid() business needs to be hidden
	   in some system-specific library functions. */
	c=fork();
	if (c==-1)
	    FAIL("fork() for authbind");
	if (c==0) {
	    char *argv[5], addrstr[33], portstr[5];
	    const char *addrfam;
	    int port;
	    afterfork();
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
	    FAIL("waitpid for authbind");
	}
	if (status) {
	    if (WIFEXITED(status) && WEXITSTATUS(status)<127) {
		int es=WEXITSTATUS(status);
		lg_perror(FAIL_LG,es,
			  "%s exited with error exit status %d;"
			  " indicates error",desc,es);
	    } else {
		lg_exitstatus(FAIL_LG,status,desc);
	    }
	    goto failed;
	}
    } else {
	if (bind(us->fd, &addr->sa, iaddr_socklen(addr))!=0)
	    FAIL("bind (%s)",iaddr_to_string(addr));
    }

    bool_t ok=record_socket_gotaddr(uc,us,failmsgclass);
    if (!ok) goto failed;

    return True;

failed:
    udp_destroy_socket(uc,us);
    return False;
}

#undef FAIL

void udp_socks_register(struct udpcommon *uc, struct udpsocks *socks,
			const char *desc)
{
    socks->uc=uc;
    socks->desc=desc;
    socks->interest=
	register_for_poll(socks,udp_socks_beforepoll,udp_socks_afterpoll,"udp");
}

void udp_socks_deregister(struct udpcommon *uc, struct udpsocks *socks)
{
    socks->uc=uc;
    deregister_for_poll(socks->interest);
}

void udp_socks_childpersist(struct udpcommon *uc, struct udpsocks *socks)
{
    int i;
    for (i=0; i<socks->n_socks; i++)
	udp_destroy_socket(uc,&socks->socks[i]);
}

static void udp_childpersist_hook(void *sst, uint32_t new_phase)
{
    struct udp *st=sst;
    udp_socks_childpersist(&st->uc,&st->socks);
}

static void udp_phase_hook(void *sst, uint32_t new_phase)
{
    struct udp *st=sst;
    struct udpsocks *socks=&st->socks;
    struct udpcommon *uc=&st->uc;
    int i;
    bool_t anydone=0;

    for (i=0; i<socks->n_socks; i++) {
	bool_t required=st->addr_configured
	    || (!anydone && i==socks->n_socks-1);
	anydone += udp_make_socket(uc,&socks->socks[i],
				   required ? M_FATAL : M_WARNING);
    }

    udp_socks_register(uc,socks, uc->use_proxy ? "proxy" : "socket");

    add_hook(PHASE_CHILDPERSIST,udp_childpersist_hook,st);
}

static list_t *udp_apply(closure_t *self, struct cloc loc, dict_t *context,
			 list_t *args)
{
    static unsigned counter;

    struct udp *st;
    list_t *caddrl;
    list_t *l;
    uint32_t a;
    int i;

    COMM_APPLY(st,&st->uc.cc,udp_,"udp",loc);
    COMM_APPLY_STANDARD(st,&st->uc.cc,"udp",args);
    UDP_APPLY_STANDARD(st,&st->uc,"udp");

    struct udpcommon *uc=&st->uc;
    struct udpsocks *socks=&st->socks;
    struct commcommon *cc=&uc->cc;

    st->counter=counter++;

    union iaddr defaultaddrs[] = {
#ifdef CONFIG_IPV6
	{ .sin6 = { .sin6_family=AF_INET6,
		    .sin6_port=htons(uc->port),
		    .sin6_addr=IN6ADDR_ANY_INIT } },
#endif
	{ .sin = { .sin_family=AF_INET,
		   .sin_port=htons(uc->port),
		   .sin_addr= { .s_addr=INADDR_ANY } } }
    };

    caddrl=dict_lookup(d,"address");
    st->addr_configured=!!caddrl;
    socks->n_socks=st->addr_configured ? list_length(caddrl)
	: (int)ARRAY_SIZE(defaultaddrs);
    if (socks->n_socks<=0 || socks->n_socks>UDP_MAX_SOCKETS)
	cfgfatal(cc->loc,"udp","`address' must be 1..%d addresses",
		 UDP_MAX_SOCKETS);

    for (i=0; i<socks->n_socks; i++) {
	struct udpsock *us=&socks->socks[i];
	if (!st->addr_configured) {
	    us->addr=defaultaddrs[i];
	} else {
	    string_item_to_iaddr(list_elem(caddrl,i),uc->port,&us->addr,"udp");
	}
	us->fd=-1;
    }

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
