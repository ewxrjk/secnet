/* User-kernel network link */

/* We will eventually support a variety of methods for extracting
   packets from the kernel: userv-ipif, ipif on its own (when we run
   as root), the kernel TUN driver, SLIP to a pty, an external netlink
   daemon. There is a performance/security tradeoff. */

/* When dealing with SLIP (to a pty, or ipif) we have separate rx, tx
   and client buffers. When receiving we may read() any amount, not
   just whole packets. When transmitting we need to bytestuff anyway,
   and may be part-way through receiving. */

/* Each netlink device is actually a router, with its own IP
   address. We do things like decreasing the TTL and recalculating the
   header checksum, generating ICMP, responding to pings, etc. */

/* This is where we have the anti-spoofing paranoia - before sending a
   packet to the kernel we check that the tunnel it came over could
   reasonably have produced it. */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "config.h"
#include "secnet.h"
#include "util.h"

#ifdef HAVE_LINUX_IF_H
#include <linux/if.h>
#include <linux/if_tun.h>
#endif

/* XXX where do we find if_tun on other architectures? */

#define DEFAULT_BUFSIZE 2048
#define DEFAULT_MTU 1000
#define ICMP_BUFSIZE 1024

#define SLIP_END    192
#define SLIP_ESC    219
#define SLIP_ESCEND 220
#define SLIP_ESCESC 221

struct netlink_client {
    struct subnet_list *networks;
    netlink_deliver_fn *deliver;
    void *dst;
    string_t name;
    bool_t can_deliver;
    struct netlink_client *next;
};

/* Netlink provides one function to the device driver, to call to deliver
   a packet from the device. The device driver provides one function to
   netlink, for it to call to deliver a packet to the device. */

struct netlink {
    closure_t cl;
    struct netlink_if ops;
    void *dst; /* Pointer to host interface state */
    string_t name;
    uint32_t max_start_pad;
    uint32_t max_end_pad;
    struct subnet_list networks;
    uint32_t local_address; /* host interface address */
    uint32_t secnet_address; /* our own address */
    uint32_t mtu;
    struct netlink_client *clients;
    netlink_deliver_fn *deliver_to_host; /* Provided by driver */
    struct buffer_if icmp; /* Buffer for assembly of outgoing ICMP */
};

/* Generic IP checksum routine */
static inline uint16_t ip_csum(uint8_t *iph,uint32_t count)
{
    register uint32_t sum=0;

    while (count>1) {
	sum+=ntohs(*(uint16_t *)iph);
	iph+=2;
	count-=2;
    }
    if(count>0)
	sum+=*(uint8_t *)iph;
    while (sum>>16)
	sum=(sum&0xffff)+(sum>>16);
    return htons(~sum);
}

#ifdef i386
/*
 *      This is a version of ip_compute_csum() optimized for IP headers,
 *      which always checksum on 4 octet boundaries.
 *
 *      By Jorge Cwik <jorge@laser.satlink.net>, adapted for linux by
 *      Arnt Gulbrandsen.
 */
static inline uint16_t ip_fast_csum(uint8_t *iph, uint32_t ihl) {
    uint32_t sum;

    __asm__ __volatile__("
            movl (%1), %0
            subl $4, %2
            jbe 2f
            addl 4(%1), %0
            adcl 8(%1), %0
            adcl 12(%1), %0
1:          adcl 16(%1), %0
            lea 4(%1), %1
            decl %2
            jne 1b
            adcl $0, %0
            movl %0, %2
            shrl $16, %0
            addw %w2, %w0
            adcl $0, %0
            notl %0
2:
            "
        /* Since the input registers which are loaded with iph and ipl
           are modified, we must also specify them as outputs, or gcc
           will assume they contain their original values. */
        : "=r" (sum), "=r" (iph), "=r" (ihl)
        : "1" (iph), "2" (ihl));
    return sum;
}
#else
static inline uint16_t ip_fast_csum(uint8_t *iph, uint32_t ihl)
{
    return ip_csum(iph,ihl*4);
}
#endif

struct iphdr {
#if defined (WORDS_BIGENDIAN)
    uint8_t    version:4,
	       ihl:4;
#else
    uint8_t    ihl:4,
	       version:4;
#endif
    uint8_t    tos;
    uint16_t   tot_len;
    uint16_t   id;
    uint16_t   frag_off;
    uint8_t    ttl;
    uint8_t    protocol;
    uint16_t   check;
    uint32_t   saddr;
    uint32_t   daddr;
    /* The options start here. */
};

struct icmphdr {
    struct iphdr iph;
    uint8_t type;
    uint8_t code;
    uint16_t check;
    union {
	uint32_t unused;
	struct {
	    uint8_t pointer;
	    uint8_t unused1;
	    uint16_t unused2;
	} pprob;
	uint32_t gwaddr;
	struct {
	    uint16_t id;
	    uint16_t seq;
	} echo;
    } d;
};
    
static void netlink_packet_deliver(struct netlink *st, struct buffer_if *buf);

static struct icmphdr *netlink_icmp_tmpl(struct netlink *st,
					 uint32_t dest,uint16_t len)
{
    struct icmphdr *h;

    BUF_ALLOC(&st->icmp,"netlink_icmp_tmpl");
    buffer_init(&st->icmp,st->max_start_pad);
    h=buf_append(&st->icmp,sizeof(*h));

    h->iph.version=4;
    h->iph.ihl=5;
    h->iph.tos=0;
    h->iph.tot_len=htons(len+(h->iph.ihl*4)+8);
    h->iph.id=0;
    h->iph.frag_off=0;
    h->iph.ttl=255;
    h->iph.protocol=1;
    h->iph.saddr=htonl(st->secnet_address);
    h->iph.daddr=htonl(dest);
    h->iph.check=0;
    h->iph.check=ip_fast_csum((uint8_t *)&h->iph,h->iph.ihl);
    h->check=0;
    h->d.unused=0;

    return h;
}

/* Fill in the ICMP checksum field correctly */
static void netlink_icmp_csum(struct icmphdr *h)
{
    uint32_t len;

    len=ntohs(h->iph.tot_len)-(4*h->iph.ihl);
    h->check=0;
    h->check=ip_csum(&h->type,len);
}

/* RFC1122:
 *       An ICMP error message MUST NOT be sent as the result of
 *       receiving:
 *
 *       *    an ICMP error message, or
 *
 *       *    a datagram destined to an IP broadcast or IP multicast
 *            address, or
 *
 *       *    a datagram sent as a link-layer broadcast, or
 *
 *       *    a non-initial fragment, or
 *
 *       *    a datagram whose source address does not define a single
 *            host -- e.g., a zero address, a loopback address, a
 *            broadcast address, a multicast address, or a Class E
 *            address.
 */
static bool_t netlink_icmp_may_reply(struct buffer_if *buf)
{
    struct iphdr *iph;
    uint32_t source;

    iph=(struct iphdr *)buf->start;
    if (iph->protocol==1) return False; /* Overly-broad; we may reply to
					   eg. icmp echo-request */
    /* How do we spot broadcast destination addresses? */
    if (ntohs(iph->frag_off)&0x1fff) return False; /* Non-initial fragment */
    source=ntohl(iph->saddr);
    if (source==0) return False;
    if ((source&0xff000000)==0x7f000000) return False;
    /* How do we spot broadcast source addresses? */
    if ((source&0xf0000000)==0xe0000000) return False; /* Multicast */
    if ((source&0xf0000000)==0xf0000000) return False; /* Class E */
    return True;
}

/* How much of the original IP packet do we include in its ICMP
   response? The header plus up to 64 bits. */
static uint16_t netlink_icmp_reply_len(struct buffer_if *buf)
{
    struct iphdr *iph=(struct iphdr *)buf->start;
    uint16_t hlen,plen;

    hlen=iph->ihl*4;
    /* We include the first 8 bytes of the packet data, provided they exist */
    hlen+=8;
    plen=ntohs(iph->tot_len);
    return (hlen>plen?plen:hlen);
}

static void netlink_icmp_simple(struct netlink *st, struct buffer_if *buf,
				uint8_t type, uint8_t code)
{
    struct iphdr *iph=(struct iphdr *)buf->start;
    struct icmphdr *h;
    uint16_t len;

    if (netlink_icmp_may_reply(buf)) {
	len=netlink_icmp_reply_len(buf);
	h=netlink_icmp_tmpl(st,ntohl(iph->saddr),len);
	h->type=type; h->code=code;
	memcpy(buf_append(&st->icmp,len),buf->start,len);
	netlink_icmp_csum(h);
	netlink_packet_deliver(st,&st->icmp);
	BUF_ASSERT_FREE(&st->icmp);
    }
}

/*
 * RFC1122: 3.1.2.2 MUST silently discard any IP frame that fails the
 * checksum.
 *
 * Is the datagram acceptable?
 *
 * 1. Length at least the size of an ip header
 * 2. Version of 4
 * 3. Checksums correctly.
 * 4. Doesn't have a bogus length
 */
static bool_t netlink_check(struct netlink *st, struct buffer_if *buf)
{
    struct iphdr *iph=(struct iphdr *)buf->start;
    uint32_t len;

    if (iph->ihl < 5 || iph->version != 4) {
	printf("ihl/version check failed\n");
	return False;
    }
    if (buf->size < iph->ihl*4) {
	printf("buffer size check failed\n");
	return False;
    }
    if (ip_fast_csum((uint8_t *)iph, iph->ihl)!=0) {
	printf("checksum failed\n");
	return False;
    }
    len=ntohs(iph->tot_len);
    /* There should be no padding */
    if (buf->size!=len || len<(iph->ihl<<2)) {
	printf("length check failed buf->size=%d len=%d\n",buf->size,len);
	return False;
    }

    /* XXX check that there's no source route specified */
    return True;
}

static void netlink_packet_deliver(struct netlink *st, struct buffer_if *buf)
{
    struct iphdr *iph=(struct iphdr *)buf->start;
    uint32_t dest=ntohl(iph->daddr);
    struct netlink_client *c;

    BUF_ASSERT_USED(buf);

    if (dest==st->secnet_address) {
	Message(M_ERROR,"%s: trying to deliver a packet to myself!\n");
	BUF_FREE(buf);
	return;
    }
    
    for (c=st->clients; c; c=c->next) {
	if (subnet_match(c->networks,dest)) {
	    if (c->can_deliver) {
		c->deliver(c->dst,c,buf);
		BUF_ASSERT_FREE(buf);
	    } else {
		/* Generate ICMP destination unreachable */
		netlink_icmp_simple(st,buf,3,0);
		BUF_FREE(buf);
	    }
	    return;
	}
    }
    if (subnet_match(&st->networks,dest)) {
	st->deliver_to_host(st->dst,NULL,buf);
	BUF_ASSERT_FREE(buf);
	return;
    }
    Message(M_ERROR,"%s: failed to deliver a packet (bad destination address)"
	    "\nXXX make this message clearer\n");
    BUF_FREE(buf);
}

static void netlink_packet_forward(struct netlink *st, struct buffer_if *buf)
{
    struct iphdr *iph=(struct iphdr *)buf->start;
    
    BUF_ASSERT_USED(buf);

    /* Packet has already been checked */
    if (iph->ttl<=1) {
	/* Generate ICMP time exceeded */
	netlink_icmp_simple(st,buf,11,0);
	BUF_FREE(buf);
	return;
    }
    iph->ttl--;
    iph->check=0;
    iph->check=ip_fast_csum((uint8_t *)iph,iph->ihl);

    netlink_packet_deliver(st,buf);
    BUF_ASSERT_FREE(buf);
}

/* Someone has been foolish enough to address a packet to us. I
   suppose we should reply to it, just to be polite. */
static void netlink_packet_local(struct netlink *st, struct buffer_if *buf)
{
    struct icmphdr *h;

    h=(struct icmphdr *)buf->start;

    if ((ntohs(h->iph.frag_off)&0xbfff)!=0) {
	Message(M_WARNING,"%s: fragmented packet addressed to us\n",st->name);
	BUF_FREE(buf);
	return;
    }

    if (h->iph.protocol==1) {
	/* It's ICMP */
	if (h->type==8 && h->code==0) {
	    /* ICMP echo-request. Special case: we re-use the buffer
	       to construct the reply. */
	    h->type=0;
	    h->iph.daddr=h->iph.saddr;
	    h->iph.saddr=htonl(st->secnet_address);
	    h->iph.ttl=255; /* Be nice and bump it up again... */
	    h->iph.check=0;
	    h->iph.check=ip_fast_csum((uint8_t *)h,h->iph.ihl);
	    netlink_icmp_csum(h);
	    netlink_packet_deliver(st,buf);
	    return;
	}
	Message(M_WARNING,"%s: unknown incoming ICMP\n",st->name);
    } else {
	/* Send ICMP protocol unreachable */
	netlink_icmp_simple(st,buf,3,2);
	BUF_FREE(buf);
	return;
    }

    BUF_FREE(buf);
}

/* Called by site code when remote packet is available */
/* buf is allocated on entry and free on return */
static void netlink_from_tunnel(void *sst, void *cst, struct buffer_if *buf)
{
    struct netlink *st=sst;
    struct netlink_client *client=cst;
    uint32_t source,dest;
    struct iphdr *iph;

    BUF_ASSERT_USED(buf);
    if (!netlink_check(st,buf)) {
	Message(M_WARNING,"%s: bad IP packet from tunnel %s\n",
		st->name,client->name);
	BUF_FREE(buf);
	return;
    }
    iph=(struct iphdr *)buf->start;

    source=ntohl(iph->saddr);
    dest=ntohl(iph->daddr);

    /* Check that the packet source is in 'nets' and its destination is
       in client->networks */
    if (!subnet_match(client->networks,source)) {
	string_t s,d;
	s=ipaddr_to_string(source);
	d=ipaddr_to_string(dest);
	Message(M_WARNING,"%s: packet from tunnel %s with bad source address "
		"(s=%s,d=%s)\n",st->name,client->name,s,d);
	free(s); free(d);
	BUF_FREE(buf);
	return;
    }
    /* (st->secnet_address needs checking before matching against
       st->networks because secnet's IP address may not be in the
       range the host is willing to deal with) */
    if (dest==st->secnet_address) {
        netlink_packet_local(st,buf);
	BUF_ASSERT_FREE(buf);
	return;
    }
    if (!subnet_match(&st->networks,dest)) {
	string_t s,d;
	s=ipaddr_to_string(source);
	d=ipaddr_to_string(dest);
	Message(M_WARNING,"%s: incoming packet from tunnel %s "
		"with bad destination address "
		"(s=%s,d=%s)\n",st->name,client->name,s,d);
	free(s); free(d);
	BUF_FREE(buf);
	return;
    }

    netlink_packet_forward(st,buf);

    BUF_ASSERT_FREE(buf);
}

/* Called by driver code when packet is received from kernel */
/* cid should be NULL */
/* buf should be allocated on entry, and is free on return */
static void netlink_from_host(void *sst, void *cid, struct buffer_if *buf)
{
    struct netlink *st=sst;
    uint32_t source,dest;
    struct iphdr *iph;

    BUF_ASSERT_USED(buf);
    if (!netlink_check(st,buf)) {
	Message(M_WARNING,"%s: bad IP packet from host\n",
		st->name);
	BUF_FREE(buf);
	return;
    }
    iph=(struct iphdr *)buf->start;

    source=ntohl(iph->saddr);
    dest=ntohl(iph->daddr);

    if (!subnet_match(&st->networks,source)) {
	string_t s,d;
	s=ipaddr_to_string(source);
	d=ipaddr_to_string(dest);
	Message(M_WARNING,"%s: outgoing packet with bad source address "
		"(s=%s,d=%s)\n",st->name,s,d);
	free(s); free(d);
	BUF_FREE(buf);
	return;
    }
    if (dest==st->secnet_address) {
	netlink_packet_local(st,buf);
	BUF_ASSERT_FREE(buf);
	return;
    }
    netlink_packet_forward(st,buf);
    BUF_ASSERT_FREE(buf);
}

static void netlink_set_delivery(void *sst, void *cid, bool_t can_deliver)
{
    struct netlink_client *c=cid;

    c->can_deliver=can_deliver;
}

static void *netlink_regnets(void *sst, struct subnet_list *nets,
			     netlink_deliver_fn *deliver, void *dst,
			     uint32_t max_start_pad, uint32_t max_end_pad,
			     string_t client_name)
{
    struct netlink *st=sst;
    struct netlink_client *c;

    Message(M_DEBUG_CONFIG,"netlink_regnets: request for %d networks, "
	    "max_start_pad=%d, max_end_pad=%d\n",
	    nets->entries,max_start_pad,max_end_pad);

    c=safe_malloc(sizeof(*c),"netlink_regnets");
    c->networks=nets;
    c->deliver=deliver;
    c->dst=dst;
    c->name=client_name; /* XXX copy it? */
    c->can_deliver=False;
    c->next=st->clients;
    st->clients=c;
    if (max_start_pad > st->max_start_pad) st->max_start_pad=max_start_pad;
    if (max_end_pad > st->max_end_pad) st->max_end_pad=max_end_pad;

    return c;
}

static netlink_deliver_fn *netlink_init(struct netlink *st,
					void *dst, struct cloc loc,
					dict_t *dict, string_t description,
					netlink_deliver_fn *to_host)
{
    st->dst=dst;
    st->cl.description=description;
    st->cl.type=CL_NETLINK;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.regnets=netlink_regnets;
    st->ops.deliver=netlink_from_tunnel;
    st->ops.set_delivery=netlink_set_delivery;
    st->max_start_pad=0;
    st->max_end_pad=0;
    st->clients=NULL;
    st->deliver_to_host=to_host;

    st->name=dict_read_string(dict,"name",False,"netlink",loc);
    if (!st->name) st->name=description;
    dict_read_subnet_list(dict, "networks", True, "netlink", loc,
			  &st->networks);
    st->local_address=string_to_ipaddr(
	dict_find_item(dict,"local-address", True, "netlink", loc),"netlink");
    st->secnet_address=string_to_ipaddr(
	dict_find_item(dict,"secnet-address", True, "netlink", loc),"netlink");
    if (!subnet_match(&st->networks,st->local_address)) {
	cfgfatal(loc,"netlink","local-address must be in local networks\n");
    }
    st->mtu=dict_read_number(dict, "mtu", False, "netlink", loc, DEFAULT_MTU);
    buffer_new(&st->icmp,ICMP_BUFSIZE);

    return netlink_from_host;
}

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
    struct netlink_client *c;
    int i;

    /* This is where we actually invoke userv - all the networks we'll
       be using should already have been registered. */

    addrs=safe_malloc(512,"userv_phase_hook:addrs");
    snprintf(addrs,512,"%s,%s,%d,slip",ipaddr_to_string(st->nl.local_address),
	     ipaddr_to_string(st->nl.secnet_address),st->nl.mtu);

    nets=safe_malloc(1024,"userv_phase_hook:nets");
    *nets=0;
    for (c=st->nl.clients; c; c=c->next) {
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
		     "netlink-userv-ipif",userv_deliver_to_kernel);

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
    BUF_ALLOC(st->buff,"netlink:userv_apply");

    st->rxfd=-1; st->txfd=-1;
    add_hook(PHASE_DROPPRIV,userv_phase_hook,st);

    return new_closure(&st->nl.cl);
}

/* Connection to the kernel through the universal TUN/TAP driver */

struct tun {
    struct netlink nl;
    int fd;
    string_t device_path;
    string_t interface_name;
    string_t ifconfig_path;
    string_t route_path;
    struct buffer_if *buff; /* We receive packets into here
			       and send them to the netlink code. */
    netlink_deliver_fn *netlink_to_tunnel;
};

static int tun_beforepoll(void *sst, struct pollfd *fds, int *nfds_io,
			  int *timeout_io, const struct timeval *tv_now,
			  uint64_t *now)
{
    struct tun *st=sst;
    *nfds_io=1;
    fds[0].fd=st->fd;
    fds[0].events=POLLIN|POLLERR|POLLHUP;
    return 0;
}

static void tun_afterpoll(void *sst, struct pollfd *fds, int nfds,
			    const struct timeval *tv_now, uint64_t *now)
{
    struct tun *st=sst;
    int l;

    if (fds[0].revents&POLLERR) {
	printf("tun_afterpoll: hup!\n");
    }
    if (fds[0].revents&POLLIN) {
	BUF_ALLOC(st->buff,"tun_afterpoll");
	buffer_init(st->buff,st->nl.max_start_pad);
	l=read(st->fd,st->buff->start,st->buff->len-st->nl.max_start_pad);
	if (l<0) {
	    fatal_perror("tun_afterpoll: read()");
	}
	if (l==0) {
	    fatal("tun_afterpoll: read()=0; device gone away?\n");
	}
	if (l>0) {
	    st->buff->size=l;
	    st->netlink_to_tunnel(&st->nl,NULL,st->buff);
	    BUF_ASSERT_FREE(st->buff);
	}
    }
}

static void tun_deliver_to_kernel(void *sst, void *cid,
				  struct buffer_if *buf)
{
    struct tun *st=sst;

    BUF_ASSERT_USED(buf);

    /* No error checking, because we'd just throw the packet away anyway */
    write(st->fd,buf->start,buf->size);
    BUF_FREE(buf);
}

static void tun_phase_hook(void *sst, uint32_t newphase)
{
    struct tun *st=sst;
    string_t hostaddr,secnetaddr;
    uint8_t mtu[6];
    string_t network,mask;
    struct netlink_client *c;
    int i;

    /* All the networks we'll be using have been registered. Invoke ifconfig
       to set the TUN device's address, and route to add routes to all
       our networks. */

    hostaddr=ipaddr_to_string(st->nl.local_address);
    secnetaddr=ipaddr_to_string(st->nl.secnet_address);
    snprintf(mtu,6,"%d",st->nl.mtu);
    mtu[5]=0;

    sys_cmd(st->ifconfig_path,"ifconfig",st->interface_name,
	    hostaddr,"netmask","255.255.255.255","-broadcast",
	    "pointopoint",secnetaddr,"mtu",mtu,"up",(char *)0);

    for (c=st->nl.clients; c; c=c->next) {
	for (i=0; i<c->networks->entries; i++) {
	    network=ipaddr_to_string(c->networks->list[i].prefix);
	    mask=ipaddr_to_string(c->networks->list[i].mask);
	    sys_cmd(st->route_path,"route","add","-net",network,
		    "netmask",mask,"gw",secnetaddr,(char *)0);
	}
    }

    /* Register for poll() */
    register_for_poll(st, tun_beforepoll, tun_afterpoll, 1, st->nl.name);
}

#ifdef HAVE_LINUX_IF_H
static list_t *tun_apply(closure_t *self, struct cloc loc, dict_t *context,
			 list_t *args)
{
    struct tun *st;
    item_t *item;
    dict_t *dict;
    struct ifreq ifr;

    st=safe_malloc(sizeof(*st),"tun_apply");

    /* First parameter must be a dict */
    item=list_elem(args,0);
    if (!item || item->type!=t_dict)
	cfgfatal(loc,"tun","parameter must be a dictionary\n");
    
    dict=item->data.dict;

    st->netlink_to_tunnel=
	netlink_init(&st->nl,st,loc,dict,
		     "netlink-tun",tun_deliver_to_kernel);

    st->device_path=dict_read_string(dict,"device",False,"tun-netlink",loc);
    st->interface_name=dict_read_string(dict,"interface",False,
					"tun-netlink",loc);
    st->ifconfig_path=dict_read_string(dict,"ifconfig-path",
				       False,"tun-netlink",loc);
    st->route_path=dict_read_string(dict,"route-path",
				    False,"tun-netlink",loc);

    if (!st->device_path) st->device_path="/dev/net/tun";
    if (!st->ifconfig_path) st->ifconfig_path="ifconfig";
    if (!st->route_path) st->route_path="route";
    st->buff=find_cl_if(dict,"buffer",CL_BUFFER,True,"tun-netlink",loc);

    /* New TUN interface: open the device, then do ioctl TUNSETIFF
       to set or find out the network interface name. */
    st->fd=open(st->device_path,O_RDWR);
    if (st->fd==-1) {
	fatal_perror("%s: can't open device file %s",st->nl.name,
		     st->device_path);
    }
    memset(&ifr,0,sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; /* Just send/receive IP packets,
					    no extra headers */
    if (st->interface_name)
	strncpy(ifr.ifr_name,st->interface_name,IFNAMSIZ);
    if (ioctl(st->fd,TUNSETIFF,&ifr)<0) {
	fatal_perror("%s: ioctl(TUNSETIFF)",st->nl.name);
    }
    if (!st->interface_name) {
	st->interface_name=safe_malloc(strlen(ifr.ifr_name)+1,"tun_apply");
	strcpy(st->interface_name,ifr.ifr_name);
	Message(M_INFO,"%s: allocated network interface %s\n",st->nl.name,
		st->interface_name);
    }

    add_hook(PHASE_DROPPRIV,tun_phase_hook,st);

    return new_closure(&st->nl.cl);
}
#endif /* HAVE_LINUX_IF_H */

static list_t *tun_old_apply(closure_t *self, struct cloc loc, dict_t *context,
			     list_t *args)
{
    struct tun *st;
    item_t *item;
    dict_t *dict;
    bool_t search_for_if;

    st=safe_malloc(sizeof(*st),"tun_old_apply");

    Message(M_WARNING,"the tun-old code has never been tested. Please report "
	    "success or failure to steve@greenend.org.uk\n");

    /* First parameter must be a dict */
    item=list_elem(args,0);
    if (!item || item->type!=t_dict)
	cfgfatal(loc,"tun","parameter must be a dictionary\n");
    
    dict=item->data.dict;

    st->netlink_to_tunnel=
	netlink_init(&st->nl,st,loc,dict,
		     "netlink-tun",tun_deliver_to_kernel);

    st->device_path=dict_read_string(dict,"device",False,"tun-netlink",loc);
    st->interface_name=dict_read_string(dict,"interface",False,
					"tun-netlink",loc);
    search_for_if=dict_read_bool(dict,"interface-search",False,"tun-netlink",
				 loc,st->device_path==NULL);
    st->ifconfig_path=dict_read_string(dict,"ifconfig-path",False,
				       "tun-netlink",loc);
    st->route_path=dict_read_string(dict,"route-path",False,"tun-netlink",loc);

    if (!st->device_path) st->device_path="/dev/tun";
    if (!st->ifconfig_path) st->ifconfig_path="ifconfig";
    if (!st->route_path) st->route_path="route";
    st->buff=find_cl_if(dict,"buffer",CL_BUFFER,True,"tun-netlink",loc);

    /* Old TUN interface: the network interface name depends on which
       /dev/tunX file we open. If 'interface-search' is set to true, treat
       'device' as the prefix and try numbers from 0--255. If it's set
       to false, treat 'device' as the whole name, and require than an
       appropriate interface name be specified. */
    if (search_for_if) {
	string_t dname;
	int i;

	if (st->interface_name) {
	    cfgfatal(loc,"tun-old","you may not specify an interface name "
		     "in interface-search mode\n");
	}
	dname=safe_malloc(strlen(st->device_path)+4,"tun_old_apply");
	st->interface_name=safe_malloc(8,"tun_old_apply");
	
	for (i=0; i<255; i++) {
	    sprintf(dname,"%s%d",st->device_path,i);
	    if ((st->fd=open(dname,O_RDWR))>0) {
		sprintf(st->interface_name,"tun%d",i);
		Message(M_INFO,"%s: allocated network interface %s "
			"through %s\n",st->nl.name,st->interface_name,dname);
		break;
	    }
	}
	if (st->fd==-1) {
	    fatal("%s: unable to open any TUN device (%s...)\n",
		  st->nl.name,st->device_path);
	}
    } else {
	if (!st->interface_name) {
	    cfgfatal(loc,"tun-old","you must specify an interface name "
		     "when you explicitly specify a TUN device file\n");
	}
	st->fd=open(st->device_path,O_RDWR);
	if (st->fd==-1) {
	    fatal_perror("%s: unable to open TUN device file %s",
			 st->nl.name,st->device_path);
	}
    }

    add_hook(PHASE_DROPPRIV,tun_phase_hook,st);

    return new_closure(&st->nl.cl);
}

/* No connection to the kernel at all... */

struct null {
    struct netlink nl;
};

static void null_deliver(void *sst, void *cid, struct buffer_if *buf)
{
    return;
}

static list_t *null_apply(closure_t *self, struct cloc loc, dict_t *context,
			  list_t *args)
{
    struct null *st;
    item_t *item;
    dict_t *dict;

    st=safe_malloc(sizeof(*st),"null_apply");

    item=list_elem(args,0);
    if (!item || item->type!=t_dict)
	cfgfatal(loc,"null-netlink","parameter must be a dictionary\n");
    
    dict=item->data.dict;

    netlink_init(&st->nl,st,loc,dict,"null-netlink",null_deliver);

    return new_closure(&st->nl.cl);
}

init_module netlink_module;
void netlink_module(dict_t *dict)
{
    add_closure(dict,"userv-ipif",userv_apply);
#ifdef HAVE_LINUX_IF_H
    add_closure(dict,"tun",tun_apply);
#endif
    add_closure(dict,"tun-old",tun_old_apply);
    add_closure(dict,"null-netlink",null_apply);
#if 0
    /* TODO */
    add_closure(dict,"pty-slip",ptyslip_apply);
    add_closure(dict,"slipd",slipd_apply);
#endif /* 0 */
}
