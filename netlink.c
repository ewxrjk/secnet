/* User-kernel network link */

/* Each netlink device is actually a router, with its own IP address.
   We do things like decreasing the TTL and recalculating the header
   checksum, generating ICMP, responding to pings, etc. */

/* This is where we have the anti-spoofing paranoia - before sending a
   packet to the kernel we check that the tunnel it came over could
   reasonably have produced it. */

#include "secnet.h"
#include "util.h"
#include "netlink.h"

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

/* Deliver a packet. "client" points to the _origin_ of the packet, not
   its destination. (May be used when sending ICMP response - avoid
   asymmetric routing.) */
static void netlink_packet_deliver(struct netlink *st,
				   struct netlink_client *client,
				   struct buffer_if *buf)
{
    struct iphdr *iph=(struct iphdr *)buf->start;
    uint32_t dest=ntohl(iph->daddr);
    uint32_t source=ntohl(iph->saddr);
    uint32_t best_quality;
    int best_match;
    int i;

    BUF_ASSERT_USED(buf);

    if (dest==st->secnet_address) {
	Message(M_ERROR,"%s: trying to deliver a packet to myself!\n");
	BUF_FREE(buf);
	return;
    }
    
    /* XXX we're going to need an extra value 'allow_route' for the
       source of the packet. It's always True for packets from the
       host. For packets from tunnels, we consult the client
       options. If !allow_route and the destination is a tunnel that
       also doesn't allow routing, we must reject the packet with an
       'administratively prohibited' or something similar ICMP. */
    if (!client) {
	/* Origin of packet is host or secnet. Might be for a tunnel. */
	best_quality=0;
	best_match=-1;
	for (i=0; i<st->n_routes; i++) {
	    if (st->routes[i].up && subnet_match(&st->routes[i].net,dest)) {
		if (st->routes[i].c->link_quality>best_quality
		    || best_quality==0) {
		    best_quality=st->routes[i].c->link_quality;
		    best_match=i;
		    /* If quality isn't perfect we may wish to
		       consider kicking the tunnel with a 0-length
		       packet to prompt it to perform a key setup.
		       Then it'll eventually decide it's up or
		       down. */
		    /* If quality is perfect we don't need to search
                       any more. */
		    if (best_quality>=MAXIMUM_LINK_QUALITY) break;
		}
	    }
	}
	if (best_match==-1) {
	    /* Not going down a tunnel. Might be for the host. 
	       XXX think about this - only situation should be if we're
	       sending ICMP. */
	    if (source!=st->secnet_address) {
		Message(M_ERROR,"netlink_packet_deliver: outgoing packet "
			"from host that won't fit down any of our tunnels!\n");
		/* XXX I think this could also occur if a soft tunnel just
		   went down, but still had packets queued in the kernel. */
		BUF_FREE(buf);
	    } else {
		st->deliver_to_host(st->dst,NULL,buf);
		BUF_ASSERT_FREE(buf);
	    }
	} else {
	    if (best_quality>0) {
		st->routes[best_match].c->deliver(
		    st->routes[best_match].c->dst,
		    st->routes[best_match].c, buf);
		BUF_ASSERT_FREE(buf);
	    } else {
		/* Generate ICMP destination unreachable */
		netlink_icmp_simple(st,buf,client,3,0); /* client==NULL */
		BUF_FREE(buf);
	    }
	}
    } else { /* client is set */
	/* We know the origin is a tunnel - packet must be for the host */
	/* XXX THIS IS NOT NECESSARILY TRUE, AND NEEDS FIXING */
	/* THIS FUNCTION MUST JUST DELIVER THE PACKET: IT MUST ASSUME
	   THE PACKET HAS ALREADY BEEN CHECKED */
	if (subnet_matches_list(&st->networks,dest)) {
	    st->deliver_to_host(st->dst,NULL,buf);
	    BUF_ASSERT_FREE(buf);
	} else {
	    Message(M_ERROR,"%s: packet from tunnel %s can't be delivered "
		    "to the host\n",st->name,client->name);
	    netlink_icmp_simple(st,buf,client,3,0);
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
static void netlink_incoming(void *sst, void *cid, struct buffer_if *buf)
{
    struct netlink *st=sst;
    struct netlink_client *client=cid;
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
    if (client) {
	/* Check that the packet source is in 'nets' and its destination is
	   in st->networks */
	if (!subnet_matches_list(client->networks,source)) {
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
	if (!subnet_matches_list(&st->networks,source)) {
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
    /* (st->secnet_address needs checking before matching destination
       addresses) */
    if (dest==st->secnet_address) {
	netlink_packet_local(st,client,buf);
	BUF_ASSERT_FREE(buf);
	return;
    }
    if (client) {
	/* Check for free routing */
	if (!subnet_matches_list(&st->networks,dest)) {
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
    }
    netlink_packet_forward(st,client,buf);
    BUF_ASSERT_FREE(buf);
}

static void netlink_set_softlinks(struct netlink *st, struct netlink_client *c,
				  bool_t up)
{
    uint32_t i;

    if (!st->routes) return; /* Table has not yet been created */
    for (i=0; i<st->n_routes; i++) {
	if (!st->routes[i].hard && st->routes[i].c==c) {
	    st->routes[i].up=up;
	    st->set_route(st->dst,&st->routes[i]);
	}
    }
}

static void netlink_set_quality(void *sst, void *cid, uint32_t quality)
{
    struct netlink *st=sst;
    struct netlink_client *c=cid;

    c->link_quality=quality;
    if (c->link_quality==LINK_QUALITY_DOWN) {
	netlink_set_softlinks(st,c,False);
    } else {
	netlink_set_softlinks(st,c,True);
    }
}

static void *netlink_regnets(void *sst, struct subnet_list *nets,
			     netlink_deliver_fn *deliver, void *dst,
			     uint32_t max_start_pad, uint32_t max_end_pad,
			     uint32_t options, string_t client_name)
{
    struct netlink *st=sst;
    struct netlink_client *c;

    Message(M_DEBUG_CONFIG,"netlink_regnets: request for %d networks, "
	    "max_start_pad=%d, max_end_pad=%d\n",
	    nets->entries,max_start_pad,max_end_pad);

    if ((options&NETLINK_OPTION_SOFTROUTE) && !st->set_route) {
	Message(M_ERROR,"%s: this netlink device does not support "
		"soft routes.\n");
	return NULL;
    }

    if (options&NETLINK_OPTION_SOFTROUTE) {
	/* XXX for now we assume that soft routes require root privilege;
	   this may not always be true. The device driver can tell us. */
	require_root_privileges=True;
	require_root_privileges_explanation="netlink: soft routes";
    }

    /* Check that nets do not intersect st->exclude_remote_networks;
       refuse to register if they do. */
    if (subnet_lists_intersect(&st->exclude_remote_networks,nets)) {
	Message(M_ERROR,"%s: site %s specifies networks that "
		"intersect with the explicitly excluded remote networks\n",
		st->name,client_name);
	return False;
    }

    c=safe_malloc(sizeof(*c),"netlink_regnets");
    c->networks=nets;
    c->deliver=deliver;
    c->dst=dst;
    c->name=client_name; /* XXX copy it? */
    c->options=options;
    c->link_quality=LINK_QUALITY_DOWN;
    c->next=st->clients;
    st->clients=c;
    if (max_start_pad > st->max_start_pad) st->max_start_pad=max_start_pad;
    if (max_end_pad > st->max_end_pad) st->max_end_pad=max_end_pad;
    st->n_routes+=nets->entries;

    return c;
}

static void netlink_dump_routes(struct netlink *st)
{
    int i;
    string_t net;

    Message(M_INFO,"%s: routing table:\n",st->name);
    for (i=0; i<st->n_routes; i++) {
	net=subnet_to_string(&st->routes[i].net);
	Message(M_INFO,"%s -> tunnel %s (%s,%s route,%s)\n",net,
		st->routes[i].c->name,
		st->routes[i].hard?"hard":"soft",
		st->routes[i].allow_route?"free":"restricted",
		st->routes[i].up?"up":"down");
	free(net);
    }
    Message(M_INFO,"%s/32 -> netlink \"%s\"\n",
	    ipaddr_to_string(st->secnet_address),st->name);
    for (i=0; i<st->networks.entries; i++) {
	net=subnet_to_string(&st->networks.list[i]);
	Message(M_INFO,"%s -> host\n",net);
	free(net);
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
	for (j=0; j<c->networks->entries; j++) {
	    st->routes[i].net=c->networks->list[j];
	    st->routes[i].c=c;
	    /* Hard routes are always up;
	       soft routes default to down */
	    st->routes[i].up=c->options&NETLINK_OPTION_SOFTROUTE?False:True;
	    st->routes[i].kup=False;
	    st->routes[i].hard=c->options&NETLINK_OPTION_SOFTROUTE?False:True;
	    st->routes[i].allow_route=c->options&NETLINK_OPTION_ALLOW_ROUTE?
		True:False;
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

    netlink_dump_routes(st);
}

netlink_deliver_fn *netlink_init(struct netlink *st,
				 void *dst, struct cloc loc,
				 dict_t *dict, string_t description,
				 netlink_route_fn *set_route,
				 netlink_deliver_fn *to_host)
{
    st->dst=dst;
    st->cl.description=description;
    st->cl.type=CL_NETLINK;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.regnets=netlink_regnets;
    st->ops.deliver=netlink_incoming;
    st->ops.set_quality=netlink_set_quality;
    st->max_start_pad=0;
    st->max_end_pad=0;
    st->clients=NULL;
    st->set_route=set_route;
    st->deliver_to_host=to_host;

    st->name=dict_read_string(dict,"name",False,"netlink",loc);
    if (!st->name) st->name=description;
    dict_read_subnet_list(dict, "networks", True, "netlink", loc,
			  &st->networks);
    dict_read_subnet_list(dict, "exclude-remote-networks", False, "netlink",
			  loc, &st->exclude_remote_networks);
    /* secnet-address does not have to be in local-networks;
       however, it should be advertised in the 'sites' file for the
       local site. */
    st->secnet_address=string_to_ipaddr(
	dict_find_item(dict,"secnet-address", True, "netlink", loc),"netlink");
    st->mtu=dict_read_number(dict, "mtu", False, "netlink", loc, DEFAULT_MTU);
    buffer_new(&st->icmp,ICMP_BUFSIZE);
    st->n_routes=0;
    st->routes=NULL;

    add_hook(PHASE_SETUP,netlink_phase_hook,st);

    return netlink_incoming;
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
	t=subnet_to_string(&route->net);
	Message(M_INFO,"%s: setting route %s to state %s\n",st->nl.name,
		t, route->up?"up":"down");
	free(t);
	route->kup=route->up;
	return True;
    }
    return False;
}
	    
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

    netlink_init(&st->nl,st,loc,dict,"null-netlink",null_set_route,
		 null_deliver);

    return new_closure(&st->nl.cl);
}

init_module netlink_module;
void netlink_module(dict_t *dict)
{
    add_closure(dict,"null-netlink",null_apply);
}
