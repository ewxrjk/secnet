/* User-kernel network link */

/* Each netlink device is actually a router, with its own IP address.
   We do things like decreasing the TTL and recalculating the header
   checksum, generating ICMP, responding to pings, etc. */

/* This is where we have the anti-spoofing paranoia - before sending a
   packet to the kernel we check that the tunnel it came over could
   reasonably have produced it. */

#include "secnet.h"
#include "util.h"
#include "ipaddr.h"
#include "netlink.h"
#include "process.h"

#define OPT_SOFTROUTE   1
#define OPT_ALLOWROUTE  2

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
    
static void netlink_packet_deliver(struct netlink *st,
				   struct netlink_client *client,
				   struct buffer_if *buf);

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
    struct icmphdr *icmph;
    uint32_t source;

    iph=(struct iphdr *)buf->start;
    icmph=(struct icmphdr *)buf->start;
    if (iph->protocol==1) {
	switch(icmph->type) {
	case 3: /* Destination unreachable */
	case 11: /* Time Exceeded */
	case 12: /* Parameter Problem */
	    return False;
	}
    }
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

/* client indicates where the packet we're constructing a response to
   comes from. NULL indicates the host. */
static void netlink_icmp_simple(struct netlink *st, struct buffer_if *buf,
				struct netlink_client *client,
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
	netlink_packet_deliver(st,NULL,&st->icmp);
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

    if (iph->ihl < 5 || iph->version != 4) return False;
    if (buf->size < iph->ihl*4) return False;
    if (ip_fast_csum((uint8_t *)iph, iph->ihl)!=0) return False;
    len=ntohs(iph->tot_len);
    /* There should be no padding */
    if (buf->size!=len || len<(iph->ihl<<2)) return False;
    /* XXX check that there's no source route specified */
    return True;
}

/* Deliver a packet. "client" is the _origin_ of the packet, not its
destination.  */
static void netlink_packet_deliver(struct netlink *st,
				   struct netlink_client *client,
				   struct buffer_if *buf)
{
    struct iphdr *iph=(struct iphdr *)buf->start;
    uint32_t dest=ntohl(iph->daddr);
    uint32_t source=ntohl(iph->saddr);
    uint32_t best_quality;
    bool_t allow_route=False;
    bool_t found_allowed=False;
    int best_match;
    int i;

    BUF_ASSERT_USED(buf);

    if (dest==st->secnet_address) {
	Message(M_ERR,"%s: trying to deliver a packet to myself!\n");
	BUF_FREE(buf);
	return;
    }
    
    /* Packets from the host (client==NULL) will always be routed.  Packets
       from clients with the allow_route option will also be routed. */
    if (!client || (client && (client->options & OPT_ALLOWROUTE)))
	allow_route=True;

    /* If !allow_route, we check the routing table anyway, and if
       there's a suitable route with OPT_ALLOWROUTE set we use it.  If
       there's a suitable route, but none with OPT_ALLOWROUTE set then
       we generate ICMP 'communication with destination network
       administratively prohibited'. */

    best_quality=0;
    best_match=-1;
    for (i=0; i<st->n_routes; i++) {
	if (st->routes[i].up && subnet_match(st->routes[i].net,dest)) {
	    /* It's an available route to the correct destination. But is
	       it better than the one we already have? */

	    /* If we have already found an allowed route then we don't
	       bother looking at routes we're not allowed to use.  If
	       we don't yet have an allowed route we'll consider any.  */
	    if (!allow_route && found_allowed) {
		if (!(st->routes[i].c->options&OPT_ALLOWROUTE)) continue;
	    }
	    
	    if (st->routes[i].c->link_quality>best_quality
		|| best_quality==0) {
		best_quality=st->routes[i].c->link_quality;
		best_match=i;
		if (st->routes[i].c->options&OPT_ALLOWROUTE)
		    found_allowed=True;
		/* If quality isn't perfect we may wish to
		   consider kicking the tunnel with a 0-length
		   packet to prompt it to perform a key setup.
		   Then it'll eventually decide it's up or
		   down. */
		/* If quality is perfect and we're allowed to use the
		   route we don't need to search any more. */
		if (best_quality>=MAXIMUM_LINK_QUALITY && 
		    (allow_route || found_allowed)) break;
	    }
	}
    }
    if (best_match==-1) {
	/* The packet's not going down a tunnel.  It might (ought to)
	   be for the host.   */
	if (ipset_contains_addr(st->networks,dest)) {
	    st->deliver_to_host(st->dst,buf);
	    st->outcount++;
	    BUF_ASSERT_FREE(buf);
	} else {
	    string_t s,d;
	    s=ipaddr_to_string(source);
	    d=ipaddr_to_string(dest);
	    Message(M_ERR,"%s: don't know where to deliver packet "
		    "(s=%s, d=%s)\n", st->name, s, d);
	    free(s); free(d);
	    netlink_icmp_simple(st,buf,client,3,0);
	    BUF_FREE(buf);
	}
    } else {
	if (!allow_route &&
	    !(st->routes[best_match].c->options&OPT_ALLOWROUTE)) {
	    string_t s,d;
	    s=ipaddr_to_string(source);
	    d=ipaddr_to_string(dest);
	    /* We have a usable route but aren't allowed to use it.
	       Generate ICMP destination unreachable: communication
	       with destination network administratively prohibited */
	    Message(M_NOTICE,"%s: denied forwarding for packet (s=%s, d=%s)\n",
		    st->name,s,d);
	    free(s); free(d);
		    
	    netlink_icmp_simple(st,buf,client,3,9);
	    BUF_FREE(buf);
	}
	if (best_quality>0) {
	    st->routes[best_match].c->deliver(
		st->routes[best_match].c->dst, buf);
	    st->routes[best_match].outcount++;
	    BUF_ASSERT_FREE(buf);
	} else {
	    /* Generate ICMP destination unreachable */
	    netlink_icmp_simple(st,buf,client,3,0); /* client==NULL */
	    BUF_FREE(buf);
	}
    }
    BUF_ASSERT_FREE(buf);
}

static void netlink_packet_forward(struct netlink *st, 
				   struct netlink_client *client,
				   struct buffer_if *buf)
{
    struct iphdr *iph=(struct iphdr *)buf->start;
    
    BUF_ASSERT_USED(buf);

    /* Packet has already been checked */
    if (iph->ttl<=1) {
	/* Generate ICMP time exceeded */
	netlink_icmp_simple(st,buf,client,11,0);
	BUF_FREE(buf);
	return;
    }
    iph->ttl--;
    iph->check=0;
    iph->check=ip_fast_csum((uint8_t *)iph,iph->ihl);

    netlink_packet_deliver(st,client,buf);
    BUF_ASSERT_FREE(buf);
}

/* Deal with packets addressed explicitly to us */
static void netlink_packet_local(struct netlink *st,
				 struct netlink_client *client,
				 struct buffer_if *buf)
{
    struct icmphdr *h;

    st->localcount++;

    h=(struct icmphdr *)buf->start;

    if ((ntohs(h->iph.frag_off)&0xbfff)!=0) {
	Message(M_WARNING,"%s: fragmented packet addressed to secnet; "
		"ignoring it\n",st->name);
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
	    netlink_packet_deliver(st,NULL,buf);
	    return;
	}
	Message(M_WARNING,"%s: unknown incoming ICMP\n",st->name);
    } else {
	/* Send ICMP protocol unreachable */
	netlink_icmp_simple(st,buf,client,3,2);
	BUF_FREE(buf);
	return;
    }

    BUF_FREE(buf);
}

/* If cid==NULL packet is from host, otherwise cid specifies which tunnel 
   it came from. */
static void netlink_incoming(struct netlink *st, struct netlink_client *client,
			     struct buffer_if *buf)
{
    uint32_t source,dest;
    struct iphdr *iph;

    BUF_ASSERT_USED(buf);
    if (!netlink_check(st,buf)) {
	Message(M_WARNING,"%s: bad IP packet from %s\n",
		st->name,client?client->name:"host");
	BUF_FREE(buf);
	return;
    }
    iph=(struct iphdr *)buf->start;

    source=ntohl(iph->saddr);
    dest=ntohl(iph->daddr);

    /* Check source */
    /* XXX consider generating ICMP if we're not point-to-point and we
       don't like the packet */
    if (client) {
	/* Check that the packet source is appropriate for the tunnel
	   it came down */
	if (!ipset_contains_addr(client->networks,source)) {
	    string_t s,d;
	    s=ipaddr_to_string(source);
	    d=ipaddr_to_string(dest);
	    Message(M_WARNING,"%s: packet from tunnel %s with bad "
		    "source address (s=%s,d=%s)\n",st->name,client->name,s,d);
	    free(s); free(d);
	    BUF_FREE(buf);
	    return;
	}
    } else {
	/* Check that the packet originates in our configured local
	   network, and hasn't been forwarded from elsewhere or
	   generated with the wrong source address */
	if (!ipset_contains_addr(st->networks,source)) {
	    string_t s,d;
	    s=ipaddr_to_string(source);
	    d=ipaddr_to_string(dest);
	    Message(M_WARNING,"%s: outgoing packet with bad source address "
		    "(s=%s,d=%s)\n",st->name,s,d);
	    free(s); free(d);
	    BUF_FREE(buf);
	    return;
	}
    }

    /* If this is a point-to-point device we don't examine the
       destination address at all; we blindly send it down our
       one-and-only registered tunnel, or to the host, depending on
       where it came from. */
    /* XXX I think we should check destination addresses */
    if (st->ptp) {
	if (client) {
	    st->deliver_to_host(st->dst,buf);
	} else {
	    st->clients->deliver(st->clients->dst,buf);
	}
	BUF_ASSERT_FREE(buf);
	return;
    }

    /* (st->secnet_address needs checking before matching destination
       addresses) */
    if (dest==st->secnet_address) {
	netlink_packet_local(st,client,buf);
	BUF_ASSERT_FREE(buf);
	return;
    }
    netlink_packet_forward(st,client,buf);
    BUF_ASSERT_FREE(buf);
}

static void netlink_inst_incoming(void *sst, struct buffer_if *buf)
{
    struct netlink_client *c=sst;
    struct netlink *st=c->nst;

    netlink_incoming(st,c,buf);
}

static void netlink_dev_incoming(void *sst, struct buffer_if *buf)
{
    struct netlink *st=sst;

    netlink_incoming(st,NULL,buf);
}

static void netlink_set_softlinks(struct netlink *st, struct netlink_client *c,
				  bool_t up, uint32_t quality)
{
    uint32_t i;

    if (!st->routes) return; /* Table has not yet been created */
    for (i=0; i<st->n_routes; i++) {
	if (st->routes[i].c==c) {
	    st->routes[i].quality=quality;
	    if (!st->routes[i].hard) {
		st->routes[i].up=up;
		st->set_route(st->dst,&st->routes[i]);
	    }
	}
    }
}

static void netlink_set_quality(void *sst, uint32_t quality)
{
    struct netlink_client *c=sst;
    struct netlink *st=c->nst;

    c->link_quality=quality;
    if (c->link_quality==LINK_QUALITY_DOWN) {
	netlink_set_softlinks(st,c,False,c->link_quality);
    } else {
	netlink_set_softlinks(st,c,True,c->link_quality);
    }
}

static void netlink_dump_routes(struct netlink *st, bool_t requested)
{
    int i;
    string_t net;
    uint32_t c=M_INFO;

    if (requested) c=M_WARNING;
    if (st->ptp) {
	net=ipaddr_to_string(st->secnet_address);
	Message(c,"%s: point-to-point (remote end is %s); routes:\n",
		st->name, net);
	free(net);
	for (i=0; i<st->n_routes; i++) {
	    net=subnet_to_string(st->routes[i].net);
	    Message(c,"%s ",net);
	    free(net);
	}
	Message(c,"\n");
    } else {
	Message(c,"%s: routing table:\n",st->name);
	for (i=0; i<st->n_routes; i++) {
	    net=subnet_to_string(st->routes[i].net);
	    Message(c,"%s -> tunnel %s (%s,%s route,%s,quality %d,use %d)\n",net,
		    st->routes[i].c->name,
		    st->routes[i].hard?"hard":"soft",
		    st->routes[i].allow_route?"free":"restricted",
		    st->routes[i].up?"up":"down",
		    st->routes[i].quality,
		    st->routes[i].outcount);
	    free(net);
	}
	net=ipaddr_to_string(st->secnet_address);
	Message(c,"%s/32 -> netlink \"%s\" (use %d)\n",
		net,st->name,st->localcount);
	free(net);
	for (i=0; i<st->subnets->entries; i++) {
	    net=subnet_to_string(st->subnets->list[i]);
	    Message(c,"%s ",net);
	    free(net);
	}
	if (i>0)
	    Message(c,"-> host (use %d)\n",st->outcount);
    }
}

static int netlink_compare_route_specificity(const void *ap, const void *bp)
{
    const struct netlink_route *a=ap;
    const struct netlink_route *b=bp;

    if (a->net.len==b->net.len) return 0;
    if (a->net.len<b->net.len) return 1;
    return -1;
}

static void netlink_phase_hook(void *sst, uint32_t new_phase)
{
    struct netlink *st=sst;
    struct netlink_client *c;
    uint32_t i,j;

    /* All the networks serviced by the various tunnels should now
     * have been registered.  We build a routing table by sorting the
     * routes into most-specific-first order.  */
    st->routes=safe_malloc(st->n_routes*sizeof(*st->routes),
			   "netlink_phase_hook");
    /* Fill the table */
    i=0;
    for (c=st->clients; c; c=c->next) {
	for (j=0; j<c->subnets->entries; j++) {
	    st->routes[i].net=c->subnets->list[j];
	    st->routes[i].c=c;
	    /* Hard routes are always up;
	       soft routes default to down; routes with no 'deliver' function
	       default to down */
	    st->routes[i].up=c->deliver?
		(c->options&OPT_SOFTROUTE?False:True):
		False;
	    st->routes[i].kup=False;
	    st->routes[i].hard=c->options&OPT_SOFTROUTE?False:True;
	    st->routes[i].allow_route=c->options&OPT_ALLOWROUTE?
		True:False;
	    st->routes[i].quality=c->link_quality;
	    st->routes[i].outcount=0;
	    i++;
	}
    }
    /* ASSERT i==st->n_routes */
    if (i!=st->n_routes) {
	fatal("netlink: route count error: expected %d got %d\n",
	      st->n_routes,i);
    }
    /* Sort the table in descending order of specificity */
    qsort(st->routes,st->n_routes,sizeof(*st->routes),
	  netlink_compare_route_specificity);

    netlink_dump_routes(st,False);
}

static void netlink_signal_handler(void *sst, int signum)
{
    struct netlink *st=sst;
    Message(M_INFO,"%s: route dump requested by SIGUSR1\n",st->name);
    netlink_dump_routes(st,True);
}

static void netlink_inst_output_config(void *sst, struct buffer_if *buf)
{
/*    struct netlink_client *c=sst; */
/*    struct netlink *st=c->nst; */

    /* For now we don't output anything */
    BUF_ASSERT_USED(buf);
}

static bool_t netlink_inst_check_config(void *sst, struct buffer_if *buf)
{
/*    struct netlink_client *c=sst; */
/*    struct netlink *st=c->nst; */

    BUF_ASSERT_USED(buf);
    /* We need to eat all of the configuration information from the buffer
       for backward compatibility. */
    buf->size=0;
    return True;
}

static void netlink_inst_reg(void *sst, netlink_deliver_fn *deliver, 
			     void *dst, uint32_t max_start_pad,
			     uint32_t max_end_pad)
{
    struct netlink_client *c=sst;
    struct netlink *st=c->nst;

    if (max_start_pad > st->max_start_pad) st->max_start_pad=max_start_pad;
    if (max_end_pad > st->max_end_pad) st->max_end_pad=max_end_pad;
    c->deliver=deliver;
    c->dst=dst;
}

static struct flagstr netlink_option_table[]={
    { "soft", OPT_SOFTROUTE },
    { "allow-route", OPT_ALLOWROUTE },
    { NULL, 0}
};
/* This is the routine that gets called when the closure that's
   returned by an invocation of a netlink device closure (eg. tun,
   userv-ipif) is invoked.  It's used to create routes and pass in
   information about them; the closure it returns is used by site
   code.  */
static closure_t *netlink_inst_create(struct netlink *st,
				      struct cloc loc, dict_t *dict)
{
    struct netlink_client *c;
    string_t name;
    struct ipset *networks;
    uint32_t options;
    list_t *l;

    name=dict_read_string(dict, "name", True, st->name, loc);

    l=dict_lookup(dict,"routes");
    if (!l)
	cfgfatal(loc,st->name,"required parameter \"routes\" not found\n");
    networks=string_list_to_ipset(l,loc,st->name,"routes");
    options=string_list_to_word(dict_lookup(dict,"options"),
				netlink_option_table,st->name);

    if ((options&OPT_SOFTROUTE) && !st->set_route) {
	cfgfatal(loc,st->name,"this netlink device does not support "
		 "soft routes.\n");
	return NULL;
    }

    if (options&OPT_SOFTROUTE) {
	/* XXX for now we assume that soft routes require root privilege;
	   this may not always be true. The device driver can tell us. */
	require_root_privileges=True;
	require_root_privileges_explanation="netlink: soft routes";
	if (st->ptp) {
	    cfgfatal(loc,st->name,"point-to-point netlinks do not support "
		     "soft routes.\n");
	    return NULL;
	}
    }

    /* Check that nets are a subset of st->remote_networks;
       refuse to register if they are not. */
    if (!ipset_is_subset(st->remote_networks,networks)) {
	cfgfatal(loc,st->name,"routes are not allowed\n");
	return NULL;
    }

    c=safe_malloc(sizeof(*c),"netlink_inst_create");
    c->cl.description=name;
    c->cl.type=CL_NETLINK;
    c->cl.apply=NULL;
    c->cl.interface=&c->ops;
    c->ops.st=c;
    c->ops.reg=netlink_inst_reg;
    c->ops.deliver=netlink_inst_incoming;
    c->ops.set_quality=netlink_set_quality;
    c->ops.output_config=netlink_inst_output_config;
    c->ops.check_config=netlink_inst_check_config;
    c->nst=st;

    c->networks=networks;
    c->subnets=ipset_to_subnet_list(networks);
    c->deliver=NULL;
    c->dst=NULL;
    c->name=name;
    c->options=options;
    c->link_quality=LINK_QUALITY_DOWN;
    c->next=st->clients;
    st->clients=c;
    st->n_routes+=c->subnets->entries;

    return &c->cl;
}

static list_t *netlink_inst_apply(closure_t *self, struct cloc loc,
				  dict_t *context, list_t *args)
{
    struct netlink *st=self->interface;

    dict_t *dict;
    item_t *item;
    closure_t *cl;

    item=list_elem(args,0);
    if (!item || item->type!=t_dict) {
	cfgfatal(loc,st->name,"must have a dictionary argument\n");
    }
    dict=item->data.dict;

    cl=netlink_inst_create(st,loc,dict);

    return new_closure(cl);
}

netlink_deliver_fn *netlink_init(struct netlink *st,
				 void *dst, struct cloc loc,
				 dict_t *dict, string_t description,
				 netlink_route_fn *set_route,
				 netlink_deliver_fn *to_host)
{
    item_t *sa, *ptpa;
    list_t *l;

    st->dst=dst;
    st->cl.description=description;
    st->cl.type=CL_PURE;
    st->cl.apply=netlink_inst_apply;
    st->cl.interface=st;
    st->max_start_pad=0;
    st->max_end_pad=0;
    st->clients=NULL;
    st->set_route=set_route;
    st->deliver_to_host=to_host;

    st->name=dict_read_string(dict,"name",False,description,loc);
    if (!st->name) st->name=description;
    l=dict_lookup(dict,"networks");
    if (l) 
	st->networks=string_list_to_ipset(l,loc,st->name,"networks");
    else {
	Message(M_WARNING,"%s: no local networks (parameter \"networks\") "
		"defined\n",st->name);
	st->networks=ipset_new();
    }
    l=dict_lookup(dict,"remote-networks");
    if (l) {
	st->remote_networks=string_list_to_ipset(l,loc,st->name,
						 "remote-networks");
    } else {
	struct ipset *empty;
	empty=ipset_new();
	st->remote_networks=ipset_complement(empty);
	ipset_free(empty);
    }

    sa=dict_find_item(dict,"secnet-address",False,"netlink",loc);
    ptpa=dict_find_item(dict,"ptp-address",False,"netlink",loc);
    if (sa && ptpa) {
	cfgfatal(loc,st->name,"you may not specify secnet-address and "
		 "ptp-address in the same netlink device\n");
    }
    if (!(sa || ptpa)) {
	cfgfatal(loc,st->name,"you must specify secnet-address or "
		 "ptp-address for this netlink device\n");
    }
    if (sa) {
	st->secnet_address=string_item_to_ipaddr(sa,"netlink");
	st->ptp=False;
    } else {
	st->secnet_address=string_item_to_ipaddr(ptpa,"netlink");
	st->ptp=True;
    }
    /* XXX we may want to subtract secnet_address from networks here, to
       be strictly correct.  It shouldn't make any practical difference,
       though, and will make the route dump look complicated... */
    st->subnets=ipset_to_subnet_list(st->networks);
    st->mtu=dict_read_number(dict, "mtu", False, "netlink", loc, DEFAULT_MTU);
    buffer_new(&st->icmp,ICMP_BUFSIZE);
    st->n_routes=0;
    st->routes=NULL;
    st->outcount=0;
    st->localcount=0;

    add_hook(PHASE_SETUP,netlink_phase_hook,st);
    request_signal_notification(SIGUSR1, netlink_signal_handler, st);

    /* If we're point-to-point then we return a CL_NETLINK directly,
       rather than a CL_NETLINK_OLD or pure closure (depending on
       compatibility).  This CL_NETLINK is for our one and only
       client.  Our cl.apply function is NULL. */
    if (st->ptp) {
	closure_t *cl;
	cl=netlink_inst_create(st,loc,dict);
	st->cl=*cl;
    }
    return netlink_dev_incoming;
}

/* No connection to the kernel at all... */

struct null {
    struct netlink nl;
};

static bool_t null_set_route(void *sst, struct netlink_route *route)
{
    struct null *st=sst;
    string_t t;

    if (route->up!=route->kup) {
	t=subnet_to_string(route->net);
	Message(M_INFO,"%s: setting route %s to state %s\n",st->nl.name,
		t, route->up?"up":"down");
	free(t);
	route->kup=route->up;
	return True;
    }
    return False;
}
	    
static void null_deliver(void *sst, struct buffer_if *buf)
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

    netlink_init(&st->nl,st,loc,dict,"null-netlink",null_set_route,
		 null_deliver);

    return new_closure(&st->nl.cl);
}

init_module netlink_module;
void netlink_module(dict_t *dict)
{
    add_closure(dict,"null-netlink",null_apply);
}
