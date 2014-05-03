/* User-kernel network link */

/* See RFCs 791, 792, 1123 and 1812 */

/* The netlink device is actually a router.  Tunnels are unnumbered
   point-to-point lines (RFC1812 section 2.2.7); the router has a
   single address (the 'router-id'). */

/* This is where we currently have the anti-spoofing paranoia - before
   sending a packet to the kernel we check that the tunnel it came
   over could reasonably have produced it. */


/* Points to note from RFC1812 (which may require changes in this
   file):

3.3.4 Maximum Transmission Unit - MTU

   The MTU of each logical interface MUST be configurable within the
   range of legal MTUs for the interface.

   Many Link Layer protocols define a maximum frame size that may be
   sent.  In such cases, a router MUST NOT allow an MTU to be set which
   would allow sending of frames larger than those allowed by the Link
   Layer protocol.  However, a router SHOULD be willing to receive a
   packet as large as the maximum frame size even if that is larger than
   the MTU.

4.2.1  A router SHOULD count datagrams discarded.

4.2.2.1 Source route options - we probably should implement processing
of source routes, even though mostly the security policy will prevent
their use.

5.3.13.4 Source Route Options

   A router MUST implement support for source route options in forwarded
   packets.  A router MAY implement a configuration option that, when
   enabled, causes all source-routed packets to be discarded.  However,
   such an option MUST NOT be enabled by default.

5.3.13.5 Record Route Option

   Routers MUST support the Record Route option in forwarded packets.

   A router MAY provide a configuration option that, if enabled, will
   cause the router to ignore (i.e., pass through unchanged) Record
   Route options in forwarded packets.  If provided, such an option MUST
   default to enabling the record-route.  This option should not affect
   the processing of Record Route options in datagrams received by the
   router itself (in particular, Record Route options in ICMP echo
   requests will still be processed according to Section [4.3.3.6]).

5.3.13.6 Timestamp Option

   Routers MUST support the timestamp option in forwarded packets.  A
   timestamp value MUST follow the rules given [INTRO:2].

   If the flags field = 3 (timestamp and prespecified address), the
   router MUST add its timestamp if the next prespecified address
   matches any of the router's IP addresses.  It is not necessary that
   the prespecified address be either the address of the interface on
   which the packet arrived or the address of the interface over which
   it will be sent.


4.2.2.7 Fragmentation: RFC 791 Section 3.2

   Fragmentation, as described in [INTERNET:1], MUST be supported by a
   router.

4.2.2.8 Reassembly: RFC 791 Section 3.2

   As specified in the corresponding section of [INTRO:2], a router MUST
   support reassembly of datagrams that it delivers to itself.

4.2.2.9 Time to Live: RFC 791 Section 3.2

   Note in particular that a router MUST NOT check the TTL of a packet
   except when forwarding it.

   A router MUST NOT discard a datagram just because it was received
   with TTL equal to zero or one; if it is to the router and otherwise
   valid, the router MUST attempt to receive it.

   On messages the router originates, the IP layer MUST provide a means
   for the transport layer to set the TTL field of every datagram that
   is sent.  When a fixed TTL value is used, it MUST be configurable.


8.1 The Simple Network Management Protocol - SNMP
8.1.1 SNMP Protocol Elements

   Routers MUST be manageable by SNMP [MGT:3].  The SNMP MUST operate
   using UDP/IP as its transport and network protocols.


*/

#include <string.h>
#include <assert.h>
#include <limits.h>
#include "secnet.h"
#include "util.h"
#include "ipaddr.h"
#include "netlink.h"
#include "process.h"

#ifdef NETLINK_DEBUG
#define MDEBUG(...) Message(M_DEBUG, __VA_ARGS__)
#else /* !NETLINK_DEBUG */
#define MDEBUG(...) ((void)0)
#endif /* !NETLINK_DEBUG */

#define ICMP_TYPE_ECHO_REPLY             0

#define ICMP_TYPE_UNREACHABLE            3
#define ICMP_CODE_NET_UNREACHABLE        0
#define ICMP_CODE_PROTOCOL_UNREACHABLE   2
#define ICMP_CODE_FRAGMENTATION_REQUIRED 4
#define ICMP_CODE_NET_PROHIBITED        13

#define ICMP_TYPE_ECHO_REQUEST           8

#define ICMP_TYPE_TIME_EXCEEDED         11
#define ICMP_CODE_TTL_EXCEEDED           0

/* Generic IP checksum routine */
static inline uint16_t ip_csum(const uint8_t *iph,int32_t count)
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
static inline uint16_t ip_fast_csum(const uint8_t *iph, int32_t ihl) {
    uint32_t sum;

    __asm__ __volatile__(
            "movl (%1), %0      ;\n"
            "subl $4, %2        ;\n"
            "jbe 2f             ;\n"
            "addl 4(%1), %0     ;\n"
            "adcl 8(%1), %0     ;\n"
            "adcl 12(%1), %0    ;\n"
"1:         adcl 16(%1), %0     ;\n"
            "lea 4(%1), %1      ;\n"
            "decl %2            ;\n"
            "jne 1b             ;\n"
            "adcl $0, %0        ;\n"
            "movl %0, %2        ;\n"
            "shrl $16, %0       ;\n"
            "addw %w2, %w0      ;\n"
            "adcl $0, %0        ;\n"
            "notl %0            ;\n"
"2:                             ;\n"
        /* Since the input registers which are loaded with iph and ipl
           are modified, we must also specify them as outputs, or gcc
           will assume they contain their original values. */
        : "=r" (sum), "=r" (iph), "=r" (ihl)
        : "1" (iph), "2" (ihl)
	: "memory");
    return sum;
}
#else
static inline uint16_t ip_fast_csum(uint8_t *iph, int32_t ihl)
{
    assert(ihl < INT_MAX/4);
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
    uint16_t   frag;
#define IPHDR_FRAG_OFF  ((uint16_t)0x1fff)
#define IPHDR_FRAG_MORE ((uint16_t)0x2000)
#define IPHDR_FRAG_DONT ((uint16_t)0x4000)
/*                 reserved        0x8000 */
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
    union icmpinfofield {
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
	struct {
	    uint16_t unused;
	    uint16_t mtu;
	} fragneeded;
    } d;
};

static const union icmpinfofield icmp_noinfo;
    
static void netlink_client_deliver(struct netlink *st,
				   struct netlink_client *client,
				   uint32_t source, uint32_t dest,
				   struct buffer_if *buf);
static void netlink_host_deliver(struct netlink *st,
				 struct netlink_client *sender,
				 uint32_t source, uint32_t dest,
				 struct buffer_if *buf);

static const char *sender_name(struct netlink_client *sender /* or NULL */)
{
    return sender?sender->name:"(local)";
}

static void netlink_packet_deliver(struct netlink *st,
				   struct netlink_client *client,
				   struct buffer_if *buf);

/* XXX RFC1812 4.3.2.5:
   All other ICMP error messages (Destination Unreachable,
   Redirect, Time Exceeded, and Parameter Problem) SHOULD have their
   precedence value set to 6 (INTERNETWORK CONTROL) or 7 (NETWORK
   CONTROL).  The IP Precedence value for these error messages MAY be
   settable.
   */
static struct icmphdr *netlink_icmp_tmpl(struct netlink *st,
					 uint32_t source, uint32_t dest,
					 uint16_t len)
{
    struct icmphdr *h;

    BUF_ALLOC(&st->icmp,"netlink_icmp_tmpl");
    buffer_init(&st->icmp,calculate_max_start_pad());
    h=buf_append(&st->icmp,sizeof(*h));

    h->iph.version=4;
    h->iph.ihl=5;
    h->iph.tos=0;
    h->iph.tot_len=htons(len+(h->iph.ihl*4)+8);
    h->iph.id=0;
    h->iph.frag=0;
    h->iph.ttl=255; /* XXX should be configurable */
    h->iph.protocol=1;
    h->iph.saddr=htonl(source);
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
    int32_t len;

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

    if (buf->size < (int)sizeof(struct icmphdr)) return False;
    iph=(struct iphdr *)buf->start;
    icmph=(struct icmphdr *)buf->start;
    if (iph->protocol==1) {
	switch(icmph->type) {
	    /* Based on http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-types
	     * as retrieved Thu, 20 Mar 2014 00:16:44 +0000.
	     * Deprecated, reserved, unassigned and experimental
	     * options are treated as not safe to reply to.
	     */
	case 0: /* Echo Reply */
	case 8: /* Echo */
	case 13: /* Timestamp */
	case 14: /* Timestamp Reply */
	    return True;
	default:
	    return False;
	}
    }
    /* How do we spot broadcast destination addresses? */
    if (ntohs(iph->frag)&IPHDR_FRAG_OFF) return False;
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

/* XXX TODO RFC1812:
4.3.2.3 Original Message Header

   Historically, every ICMP error message has included the Internet
   header and at least the first 8 data bytes of the datagram that
   triggered the error.  This is no longer adequate, due to the use of
   IP-in-IP tunneling and other technologies.  Therefore, the ICMP
   datagram SHOULD contain as much of the original datagram as possible
   without the length of the ICMP datagram exceeding 576 bytes.  The
   returned IP header (and user data) MUST be identical to that which
   was received, except that the router is not required to undo any
   modifications to the IP header that are normally performed in
   forwarding that were performed before the error was detected (e.g.,
   decrementing the TTL, or updating options).  Note that the
   requirements of Section [4.3.3.5] supersede this requirement in some
   cases (i.e., for a Parameter Problem message, if the problem is in a
   modified field, the router must undo the modification).  See Section
   [4.3.3.5]).
   */
static uint16_t netlink_icmp_reply_len(struct buffer_if *buf)
{
    if (buf->size < (int)sizeof(struct iphdr)) return 0;
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
static void netlink_icmp_simple(struct netlink *st,
				struct netlink_client *origsender,
				struct buffer_if *buf,
				uint8_t type, uint8_t code,
				union icmpinfofield info)
{
    struct icmphdr *h;
    uint16_t len;

    if (netlink_icmp_may_reply(buf)) {
	struct iphdr *iph=(struct iphdr *)buf->start;

	uint32_t icmpdest = ntohl(iph->saddr);
	uint32_t icmpsource;
	const char *icmpsourcedebugprefix;
	if (!st->ptp) {
	    icmpsource=st->secnet_address;
	    icmpsourcedebugprefix="";
	} else if (origsender) {
	    /* was from peer, send reply as if from host */
	    icmpsource=st->local_address;
	    icmpsourcedebugprefix="L!";
	} else {
	    /* was from host, send reply as if from peer */
	    icmpsource=st->secnet_address; /* actually, peer address */
	    icmpsourcedebugprefix="P!";
	}
	MDEBUG("%s: generating ICMP re %s[%s]->[%s]:"
	       " from %s%s type=%u code=%u\n",
	       st->name, sender_name(origsender),
	       ipaddr_to_string(ntohl(iph->saddr)),
	       ipaddr_to_string(ntohl(iph->daddr)),
	       icmpsourcedebugprefix,
	       ipaddr_to_string(icmpsource),
	       type, code);

	len=netlink_icmp_reply_len(buf);
	h=netlink_icmp_tmpl(st,icmpsource,icmpdest,len);
	h->type=type; h->code=code; h->d=info;
	memcpy(buf_append(&st->icmp,len),buf->start,len);
	netlink_icmp_csum(h);

	if (!st->ptp) {
	    netlink_packet_deliver(st,NULL,&st->icmp);
	} else if (origsender) {
	    netlink_client_deliver(st,origsender,icmpsource,icmpdest,&st->icmp);
	} else {
	    netlink_host_deliver(st,NULL,icmpsource,icmpdest,&st->icmp);
	}
	BUF_ASSERT_FREE(&st->icmp);
    }
}

/*
 * RFC1122: 3.1.2.2 MUST silently discard any IP frame that fails the
 * checksum.
 * RFC1812: 4.2.2.5 MUST discard messages containing invalid checksums.
 *
 * Is the datagram acceptable?
 *
 * 1. Length at least the size of an ip header
 * 2. Version of 4
 * 3. Checksums correctly.
 * 4. Doesn't have a bogus length
 */
static bool_t netlink_check(struct netlink *st, struct buffer_if *buf,
			    char *errmsgbuf, int errmsgbuflen)
{
#define BAD(...) do{					\
	snprintf(errmsgbuf,errmsgbuflen,__VA_ARGS__);	\
	return False;					\
    }while(0)

    if (buf->size < (int)sizeof(struct iphdr)) BAD("len %"PRIu32"",buf->size);
    struct iphdr *iph=(struct iphdr *)buf->start;
    int32_t len;

    if (iph->ihl < 5) BAD("ihl %u",iph->ihl);
    if (iph->version != 4) BAD("version %u",iph->version);
    if (buf->size < iph->ihl*4) BAD("size %"PRId32"<%u*4",buf->size,iph->ihl);
    if (ip_fast_csum((uint8_t *)iph, iph->ihl)!=0) BAD("csum");
    len=ntohs(iph->tot_len);
    /* There should be no padding */
    if (buf->size!=len) BAD("len %"PRId32"!=%"PRId32,buf->size,len);
    if (len<(iph->ihl<<2)) BAD("len %"PRId32"<(%u<<2)",len,iph->ihl);
    /* XXX check that there's no source route specified */
    return True;

#undef BAD
}

static const char *fragment_filter_header(uint8_t *base, long *hlp)
{
    const int fixedhl = sizeof(struct iphdr);
    long hl = *hlp;
    const uint8_t *ipend = base + hl;
    uint8_t *op = base + fixedhl;
    const uint8_t *ip = op;

    while (ip < ipend) {
	uint8_t opt = ip[0];
	int remain = ipend - ip;
	if (opt == 0x00) /* End of Options List */ break;
	if (opt == 0x01) /* No Operation */ continue;
	if (remain < 2) return "IPv4 options truncated at length";
	int optlen = ip[1];
	if (remain < optlen) return "IPv4 options truncated in option";
	if (opt & 0x80) /* copy */ {
	    memmove(op, ip, optlen);
	    op += optlen;
	}
	ip += optlen;
    }
    while ((hl = (op - base)) & 0x3)
	*op++ = 0x00 /* End of Option List */;
    ((struct iphdr*)base)->ihl = hl >> 2;
    *hlp = hl;

    return 0;
}

/* Fragment or send ICMP Fragmentation Needed */
static void netlink_maybe_fragment(struct netlink *st,
				   struct netlink_client *sender,
				   netlink_deliver_fn *deliver,
				   void *deliver_dst,
				   const char *delivery_name,
				   int32_t mtu,
				   uint32_t source, uint32_t dest,
				   struct buffer_if *buf)
{
    struct iphdr *iph=(struct iphdr*)buf->start;
    long hl = iph->ihl*4;
    const char *ssource = ipaddr_to_string(source);

    if (buf->size <= mtu) {
	deliver(deliver_dst, buf);
	return;
    }

    MDEBUG("%s: fragmenting %s->%s org.size=%"PRId32"\n",
	   st->name, ssource, delivery_name, buf->size);

#define BADFRAG(m, ...)					\
	Message(M_WARNING,				\
	        "%s: fragmenting packet from source %s"	\
		" for transmission via %s: " m "\n",	\
		st->name, ssource, delivery_name,	\
		## __VA_ARGS__);

    unsigned orig_frag = ntohs(iph->frag);

    if (orig_frag&IPHDR_FRAG_DONT) {
	union icmpinfofield info =
	    { .fragneeded = { .unused = 0, .mtu = htons(mtu) } };
	netlink_icmp_simple(st,sender,buf,
			    ICMP_TYPE_UNREACHABLE,
			    ICMP_CODE_FRAGMENTATION_REQUIRED,
			    info);
	BUF_FREE(buf);
	return;
    }
    if (mtu < hl + 8) {
	BADFRAG("mtu %"PRId32" too small", mtu);
	BUF_FREE(buf);
	return;
    }

    /* we (ab)use the icmp buffer to stash the original packet */
    struct buffer_if *orig = &st->icmp;
    BUF_ALLOC(orig,"netlink_client_deliver fragment orig");
    buffer_copy(orig,buf);
    BUF_FREE(buf);

    const uint8_t *startindata = orig->start + hl;
    const uint8_t *indata =      startindata;
    const uint8_t *endindata =   orig->start + orig->size;
    _Bool filtered = 0;

    for (;;) {
	/* compute our fragment offset */
	long dataoffset = indata - startindata
	    + (orig_frag & IPHDR_FRAG_OFF)*8;
	assert(!(dataoffset & 7));
	if (dataoffset > IPHDR_FRAG_OFF*8) {
	    BADFRAG("ultimate fragment offset out of range");
	    break;
	}

	BUF_ALLOC(buf,"netlink_client_deliver fragment frag");
	buffer_init(buf,calculate_max_start_pad());

	/* copy header (possibly filtered); will adjust in a bit */
	struct iphdr *fragh = buf_append(buf, hl);
	memcpy(fragh, orig->start, hl);

	/* decide how much payload to copy and copy it */
	long avail = mtu - hl;
	long remain = endindata - indata;
	long use = avail < remain ? (avail & ~(long)7) : remain;
	memcpy(buf_append(buf, use), indata, use);
	indata += use;

	_Bool last_frag = indata >= endindata;

	/* adjust the header */
	fragh->tot_len = htons(buf->size);
	fragh->frag =
	    htons((orig_frag & ~IPHDR_FRAG_OFF) |
		  (last_frag ? 0 : IPHDR_FRAG_MORE) |
		  (dataoffset >> 3));
	fragh->check = 0;
	fragh->check = ip_fast_csum((const void*)fragh, fragh->ihl);

	/* actually send it */
	deliver(deliver_dst, buf);
	if (last_frag)
	    break;

	/* after copying the header for the first frag,
	 * we filter the header for the remaining frags */
	if (!filtered++) {
	    const char *bad = fragment_filter_header(orig->start, &hl);
	    if (bad) { BADFRAG("%s", bad); break; }
	}
    }

    BUF_FREE(orig);

#undef BADFRAG
}

/* Deliver a packet _to_ client; used after we have decided
 * what to do with it (and just to check that the client has
 * actually registered a delivery function with us). */
static void netlink_client_deliver(struct netlink *st,
				   struct netlink_client *client,
				   uint32_t source, uint32_t dest,
				   struct buffer_if *buf)
{
    if (!client->deliver) {
	string_t s,d;
	s=ipaddr_to_string(source);
	d=ipaddr_to_string(dest);
	Message(M_ERR,"%s: dropping %s->%s, client not registered\n",
		st->name,s,d);
	free(s); free(d);
	BUF_FREE(buf);
	return;
    }
    netlink_maybe_fragment(st,NULL, client->deliver,client->dst,client->name,
			   client->mtu, source,dest,buf);
    client->outcount++;
}

/* Deliver a packet to the host; used after we have decided that that
 * is what to do with it. */
static void netlink_host_deliver(struct netlink *st,
				 struct netlink_client *sender,
				 uint32_t source, uint32_t dest,
				 struct buffer_if *buf)
{
    netlink_maybe_fragment(st,sender, st->deliver_to_host,st->dst,"(host)",
			   st->mtu, source,dest,buf);
    st->outcount++;
}

/* Deliver a packet. "sender"==NULL for packets from the host and packets
   generated internally in secnet.  */
static void netlink_packet_deliver(struct netlink *st,
				   struct netlink_client *sender,
				   struct buffer_if *buf)
{
    if (buf->size < (int)sizeof(struct iphdr)) {
	Message(M_ERR,"%s: trying to deliver a too-short packet"
		" from %s!\n",st->name, sender_name(sender));
	BUF_FREE(buf);
	return;
    }

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
	Message(M_ERR,"%s: trying to deliver a packet to myself!\n",st->name);
	BUF_FREE(buf);
	return;
    }
    
    /* Packets from the host (sender==NULL) may always be routed.  Packets
       from clients with the allow_route option will also be routed. */
    if (!sender || (sender && (sender->options & OPT_ALLOWROUTE)))
	allow_route=True;

    /* If !allow_route, we check the routing table anyway, and if
       there's a suitable route with OPT_ALLOWROUTE set we use it.  If
       there's a suitable route, but none with OPT_ALLOWROUTE set then
       we generate ICMP 'communication with destination network
       administratively prohibited'. */

    best_quality=0;
    best_match=-1;
    for (i=0; i<st->n_clients; i++) {
	if (st->routes[i]->up &&
	    ipset_contains_addr(st->routes[i]->networks,dest)) {
	    /* It's an available route to the correct destination. But is
	       it better than the one we already have? */

	    /* If we have already found an allowed route then we don't
	       bother looking at routes we're not allowed to use.  If
	       we don't yet have an allowed route we'll consider any.  */
	    if (!allow_route && found_allowed) {
		if (!(st->routes[i]->options&OPT_ALLOWROUTE)) continue;
	    }
	    
	    if (st->routes[i]->link_quality>best_quality
		|| best_quality==0) {
		best_quality=st->routes[i]->link_quality;
		best_match=i;
		if (st->routes[i]->options&OPT_ALLOWROUTE)
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
	    netlink_host_deliver(st,sender,source,dest,buf);
	    BUF_ASSERT_FREE(buf);
	} else {
	    string_t s,d;
	    s=ipaddr_to_string(source);
	    d=ipaddr_to_string(dest);
	    Message(M_DEBUG,"%s: don't know where to deliver packet "
		    "(s=%s, d=%s)\n", st->name, s, d);
	    free(s); free(d);
	    netlink_icmp_simple(st,sender,buf,ICMP_TYPE_UNREACHABLE,
				ICMP_CODE_NET_UNREACHABLE, icmp_noinfo);
	    BUF_FREE(buf);
	}
    } else {
	if (!allow_route &&
	    !(st->routes[best_match]->options&OPT_ALLOWROUTE)) {
	    string_t s,d;
	    s=ipaddr_to_string(source);
	    d=ipaddr_to_string(dest);
	    /* We have a usable route but aren't allowed to use it.
	       Generate ICMP destination unreachable: communication
	       with destination network administratively prohibited */
	    Message(M_NOTICE,"%s: denied forwarding for packet (s=%s, d=%s)\n",
		    st->name,s,d);
	    free(s); free(d);
		    
	    netlink_icmp_simple(st,sender,buf,ICMP_TYPE_UNREACHABLE,
				ICMP_CODE_NET_PROHIBITED, icmp_noinfo);
	    BUF_FREE(buf);
	} else {
	    if (best_quality>0) {
		netlink_client_deliver(st,st->routes[best_match],
				       source,dest,buf);
		BUF_ASSERT_FREE(buf);
	    } else {
		/* Generate ICMP destination unreachable */
		netlink_icmp_simple(st,sender,buf,
				    ICMP_TYPE_UNREACHABLE,
				    ICMP_CODE_NET_UNREACHABLE,
				    icmp_noinfo);
		BUF_FREE(buf);
	    }
	}
    }
    BUF_ASSERT_FREE(buf);
}

static void netlink_packet_forward(struct netlink *st, 
				   struct netlink_client *sender,
				   struct buffer_if *buf)
{
    if (buf->size < (int)sizeof(struct iphdr)) return;
    struct iphdr *iph=(struct iphdr *)buf->start;
    
    BUF_ASSERT_USED(buf);

    /* Packet has already been checked */
    if (iph->ttl<=1) {
	/* Generate ICMP time exceeded */
	netlink_icmp_simple(st,sender,buf,ICMP_TYPE_TIME_EXCEEDED,
			    ICMP_CODE_TTL_EXCEEDED,icmp_noinfo);
	BUF_FREE(buf);
	return;
    }
    iph->ttl--;
    iph->check=0;
    iph->check=ip_fast_csum((uint8_t *)iph,iph->ihl);

    netlink_packet_deliver(st,sender,buf);
    BUF_ASSERT_FREE(buf);
}

/* Deal with packets addressed explicitly to us */
static void netlink_packet_local(struct netlink *st,
				 struct netlink_client *sender,
				 struct buffer_if *buf)
{
    struct icmphdr *h;

    st->localcount++;

    if (buf->size < (int)sizeof(struct icmphdr)) {
	Message(M_WARNING,"%s: short packet addressed to secnet; "
		"ignoring it\n",st->name);
	BUF_FREE(buf);
	return;
    }
    h=(struct icmphdr *)buf->start;

    unsigned fraginfo = ntohs(h->iph.frag);
    if ((fraginfo&(IPHDR_FRAG_OFF|IPHDR_FRAG_MORE))!=0) {
	if (!(fraginfo & IPHDR_FRAG_OFF))
	    /* report only for first fragment */
	    Message(M_WARNING,"%s: fragmented packet addressed to secnet; "
		    "ignoring it\n",st->name);
	BUF_FREE(buf);
	return;
    }

    if (h->iph.protocol==1) {
	/* It's ICMP */
	if (h->type==ICMP_TYPE_ECHO_REQUEST && h->code==0) {
	    /* ICMP echo-request. Special case: we re-use the buffer
	       to construct the reply. */
	    h->type=ICMP_TYPE_ECHO_REPLY;
	    h->iph.daddr=h->iph.saddr;
	    h->iph.saddr=htonl(st->secnet_address);
	    h->iph.ttl=255;
	    h->iph.check=0;
	    h->iph.check=ip_fast_csum((uint8_t *)h,h->iph.ihl);
	    netlink_icmp_csum(h);
	    netlink_packet_deliver(st,NULL,buf);
	    return;
	}
	Message(M_WARNING,"%s: unknown incoming ICMP\n",st->name);
    } else {
	/* Send ICMP protocol unreachable */
	netlink_icmp_simple(st,sender,buf,ICMP_TYPE_UNREACHABLE,
			    ICMP_CODE_PROTOCOL_UNREACHABLE,icmp_noinfo);
	BUF_FREE(buf);
	return;
    }

    BUF_FREE(buf);
}

/* If cid==NULL packet is from host, otherwise cid specifies which tunnel 
   it came from. */
static void netlink_incoming(struct netlink *st, struct netlink_client *sender,
			     struct buffer_if *buf)
{
    uint32_t source,dest;
    struct iphdr *iph;
    char errmsgbuf[50];
    const char *sourcedesc=sender?sender->name:"host";

    BUF_ASSERT_USED(buf);

    if (!netlink_check(st,buf,errmsgbuf,sizeof(errmsgbuf))) {
	Message(M_WARNING,"%s: bad IP packet from %s: %s\n",
		st->name,sourcedesc,
		errmsgbuf);
	BUF_FREE(buf);
	return;
    }
    assert(buf->size >= (int)sizeof(struct iphdr));
    iph=(struct iphdr *)buf->start;

    source=ntohl(iph->saddr);
    dest=ntohl(iph->daddr);

    /* Check source. If we don't like the source, there's no point
       generating ICMP because we won't know how to get it to the
       source of the packet. */
    if (sender) {
	/* Check that the packet source is appropriate for the tunnel
	   it came down */
	if (!ipset_contains_addr(sender->networks,source)) {
	    string_t s,d;
	    s=ipaddr_to_string(source);
	    d=ipaddr_to_string(dest);
	    Message(M_WARNING,"%s: packet from tunnel %s with bad "
		    "source address (s=%s,d=%s)\n",st->name,sender->name,s,d);
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
       where it came from.  It's up to external software to check
       address validity and generate ICMP, etc. */
    if (st->ptp) {
	if (sender) {
	    netlink_host_deliver(st,sender,source,dest,buf);
	} else {
	    netlink_client_deliver(st,st->clients,source,dest,buf);
	}
	BUF_ASSERT_FREE(buf);
	return;
    }

    /* st->secnet_address needs checking before matching destination
       addresses */
    if (dest==st->secnet_address) {
	netlink_packet_local(st,sender,buf);
	BUF_ASSERT_FREE(buf);
	return;
    }
    netlink_packet_forward(st,sender,buf);
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

static void netlink_set_quality(void *sst, uint32_t quality)
{
    struct netlink_client *c=sst;
    struct netlink *st=c->nst;

    c->link_quality=quality;
    c->up=(c->link_quality==LINK_QUALITY_DOWN)?False:True;
    if (c->options&OPT_SOFTROUTE) {
	st->set_routes(st->dst,c);
    }
}

static void netlink_output_subnets(struct netlink *st, uint32_t loglevel,
				   struct subnet_list *snets)
{
    int32_t i;
    string_t net;

    for (i=0; i<snets->entries; i++) {
	net=subnet_to_string(snets->list[i]);
	Message(loglevel,"%s ",net);
	free(net);
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
	Message(c,"%s: point-to-point (remote end is %s); routes: ",
		st->name, net);
	free(net);
	netlink_output_subnets(st,c,st->clients->subnets);
	Message(c,"\n");
    } else {
	Message(c,"%s: routing table:\n",st->name);
	for (i=0; i<st->n_clients; i++) {
	    netlink_output_subnets(st,c,st->routes[i]->subnets);
	    Message(c,"-> tunnel %s (%s,mtu %d,%s routes,%s,"
		    "quality %d,use %d,pri %lu)\n",
		    st->routes[i]->name,
		    st->routes[i]->up?"up":"down",
		    st->routes[i]->mtu,
		    st->routes[i]->options&OPT_SOFTROUTE?"soft":"hard",
		    st->routes[i]->options&OPT_ALLOWROUTE?"free":"restricted",
		    st->routes[i]->link_quality,
		    st->routes[i]->outcount,
		    (unsigned long)st->routes[i]->priority);
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

/* ap is a pointer to a member of the routes array */
static int netlink_compare_client_priority(const void *ap, const void *bp)
{
    const struct netlink_client *const*a=ap;
    const struct netlink_client *const*b=bp;

    if ((*a)->priority==(*b)->priority) return 0;
    if ((*a)->priority<(*b)->priority) return 1;
    return -1;
}

static void netlink_phase_hook(void *sst, uint32_t new_phase)
{
    struct netlink *st=sst;
    struct netlink_client *c;
    int32_t i;

    /* All the networks serviced by the various tunnels should now
     * have been registered.  We build a routing table by sorting the
     * clients by priority.  */
    st->routes=safe_malloc_ary(sizeof(*st->routes),st->n_clients,
			       "netlink_phase_hook");
    /* Fill the table */
    i=0;
    for (c=st->clients; c; c=c->next) {
	assert(i<INT_MAX);
	st->routes[i++]=c;
    }
    /* Sort the table in descending order of priority */
    qsort(st->routes,st->n_clients,sizeof(*st->routes),
	  netlink_compare_client_priority);

    netlink_dump_routes(st,False);
}

static void netlink_signal_handler(void *sst, int signum)
{
    struct netlink *st=sst;
    Message(M_INFO,"%s: route dump requested by SIGUSR1\n",st->name);
    netlink_dump_routes(st,True);
}

static void netlink_inst_set_mtu(void *sst, int32_t new_mtu)
{
    struct netlink_client *c=sst;

    c->mtu=new_mtu;
}

static void netlink_inst_reg(void *sst, netlink_deliver_fn *deliver, 
			     void *dst, uint32_t *localmtu_r)
{
    struct netlink_client *c=sst;
    struct netlink *st=c->nst;

    c->deliver=deliver;
    c->dst=dst;

    if (localmtu_r)
	*localmtu_r=st->mtu;
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
    uint32_t options,priority;
    int32_t mtu;
    list_t *l;

    name=dict_read_string(dict, "name", True, st->name, loc);

    l=dict_lookup(dict,"routes");
    if (!l)
	cfgfatal(loc,st->name,"required parameter \"routes\" not found\n");
    networks=string_list_to_ipset(l,loc,st->name,"routes");
    options=string_list_to_word(dict_lookup(dict,"options"),
				netlink_option_table,st->name);

    priority=dict_read_number(dict,"priority",False,st->name,loc,0);
    mtu=dict_read_number(dict,"mtu",False,st->name,loc,0);

    if ((options&OPT_SOFTROUTE) && !st->set_routes) {
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
    c->ops.set_mtu=netlink_inst_set_mtu;
    c->nst=st;

    c->networks=networks;
    c->subnets=ipset_to_subnet_list(networks);
    c->priority=priority;
    c->deliver=NULL;
    c->dst=NULL;
    c->name=name;
    c->link_quality=LINK_QUALITY_UNUSED;
    c->mtu=mtu?mtu:st->mtu;
    c->options=options;
    c->outcount=0;
    c->up=False;
    c->kup=False;
    c->next=st->clients;
    st->clients=c;
    assert(st->n_clients < INT_MAX);
    st->n_clients++;

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
				 dict_t *dict, cstring_t description,
				 netlink_route_fn *set_routes,
				 netlink_deliver_fn *to_host)
{
    item_t *sa, *ptpa;
    list_t *l;

    st->dst=dst;
    st->cl.description=description;
    st->cl.type=CL_PURE;
    st->cl.apply=netlink_inst_apply;
    st->cl.interface=st;
    st->clients=NULL;
    st->routes=NULL;
    st->n_clients=0;
    st->set_routes=set_routes;
    st->deliver_to_host=to_host;

    st->name=dict_read_string(dict,"name",False,description,loc);
    if (!st->name) st->name=description;
    l=dict_lookup(dict,"networks");
    if (l) 
	st->networks=string_list_to_ipset(l,loc,st->name,"networks");
    else {
	struct ipset *empty;
	empty=ipset_new();
	st->networks=ipset_complement(empty);
	ipset_free(empty);
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
    st->local_address=string_item_to_ipaddr(
	dict_find_item(dict,"local-address", True, "netlink", loc),"netlink");

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
    /* To be strictly correct we could subtract secnet_address from
       networks here.  It shouldn't make any practical difference,
       though, and will make the route dump look complicated... */
    st->subnets=ipset_to_subnet_list(st->networks);
    st->mtu=dict_read_number(dict, "mtu", False, "netlink", loc, DEFAULT_MTU);
    buffer_new(&st->icmp,MAX(ICMP_BUFSIZE,st->mtu));
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

static bool_t null_set_route(void *sst, struct netlink_client *routes)
{
    struct null *st=sst;

    if (routes->up!=routes->kup) {
	Message(M_INFO,"%s: setting routes for tunnel %s to state %s\n",
		st->nl.name,routes->name,
		routes->up?"up":"down");
	routes->kup=routes->up;
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

void netlink_module(dict_t *dict)
{
    add_closure(dict,"null-netlink",null_apply);
}
