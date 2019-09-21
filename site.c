/* site.c - manage communication with a remote network site */

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

/* The 'site' code doesn't know anything about the structure of the
   packets it's transmitting.  In fact, under the new netlink
   configuration scheme it doesn't need to know anything at all about
   IP addresses, except how to contact its peer.  This means it could
   potentially be used to tunnel other protocols too (IPv6, IPX, plain
   old Ethernet frames) if appropriate netlink code can be written
   (and that ought not to be too hard, eg. using the TUN/TAP device to
   pretend to be an Ethernet interface).  */

/* At some point in the future the netlink code will be asked for
   configuration information to go in the PING/PONG packets at the end
   of the key exchange. */

#include "secnet.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <sys/socket.h>

#include <sys/mman.h>
#include "util.h"
#include "unaligned.h"
#include "magic.h"

#define SETUP_BUFFER_LEN 2048

#define DEFAULT_KEY_LIFETIME                  (3600*1000) /* [ms] */
#define DEFAULT_KEY_RENEGOTIATE_GAP           (5*60*1000) /* [ms] */
#define DEFAULT_SETUP_RETRIES 5
#define DEFAULT_SETUP_RETRY_INTERVAL             (2*1000) /* [ms] */
#define DEFAULT_WAIT_TIME                       (20*1000) /* [ms] */

#define DEFAULT_MOBILE_KEY_LIFETIME      (2*24*3600*1000) /* [ms] */
#define DEFAULT_MOBILE_KEY_RENEGOTIATE_GAP (12*3600*1000) /* [ms] */
#define DEFAULT_MOBILE_SETUP_RETRIES 30
#define DEFAULT_MOBILE_SETUP_RETRY_INTERVAL      (1*1000) /* [ms] */
#define DEFAULT_MOBILE_WAIT_TIME                (10*1000) /* [ms] */

#define DEFAULT_MOBILE_PEER_EXPIRY            (2*60)      /* [s] */

/* Each site can be in one of several possible states. */

/* States:
   SITE_STOP         - nothing is allowed to happen; tunnel is down;
                       all session keys have been erased
     -> SITE_RUN upon external instruction
   SITE_RUN          - site up, maybe with valid key
     -> SITE_RESOLVE upon outgoing packet and no valid key
         we start name resolution for the other end of the tunnel
     -> SITE_SENTMSG2 upon valid incoming message 1 and suitable time
         we send an appropriate message 2
   SITE_RESOLVE      - waiting for name resolution
     -> SITE_SENTMSG1 upon successful resolution
         we send an appropriate message 1
     -> SITE_SENTMSG2 upon valid incoming message 1 (then abort resolution)
         we abort resolution and 
     -> SITE_WAIT on timeout or resolution failure
   SITE_SENTMSG1
     -> SITE_SENTMSG2 upon valid incoming message 1 from higher priority end
     -> SITE_SENTMSG3 upon valid incoming message 2
     -> SITE_WAIT on timeout
   SITE_SENTMSG2
     -> SITE_SENTMSG4 upon valid incoming message 3
     -> SITE_WAIT on timeout
   SITE_SENTMSG3
     -> SITE_SENTMSG5 upon valid incoming message 4
     -> SITE_WAIT on timeout
   SITE_SENTMSG4
     -> SITE_RUN upon valid incoming message 5
     -> SITE_WAIT on timeout
   SITE_SENTMSG5
     -> SITE_RUN upon valid incoming message 6
     -> SITE_WAIT on timeout
   SITE_WAIT         - failed to establish key; do nothing for a while
     -> SITE_RUN on timeout
   */

#define SITE_STOP     0
#define SITE_RUN      1
#define SITE_RESOLVE  2
#define SITE_SENTMSG1 3
#define SITE_SENTMSG2 4
#define SITE_SENTMSG3 5
#define SITE_SENTMSG4 6
#define SITE_SENTMSG5 7
#define SITE_WAIT     8

#define CASES_MSG3_KNOWN LABEL_MSG3: case LABEL_MSG3BIS

struct msg;

int32_t site_max_start_pad = 4*4;

static cstring_t state_name(uint32_t state)
{
    switch (state) {
    case 0: return "STOP";
    case 1: return "RUN";
    case 2: return "RESOLVE";
    case 3: return "SENTMSG1";
    case 4: return "SENTMSG2";
    case 5: return "SENTMSG3";
    case 6: return "SENTMSG4";
    case 7: return "SENTMSG5";
    case 8: return "WAIT";
    default: return "*bad state*";
    }
}

#define NONCELEN 8

#define LOG_UNEXPECTED    0x00000001
#define LOG_SETUP_INIT    0x00000002
#define LOG_SETUP_TIMEOUT 0x00000004
#define LOG_ACTIVATE_KEY  0x00000008
#define LOG_TIMEOUT_KEY   0x00000010
#define LOG_SEC           0x00000020
#define LOG_STATE         0x00000040
#define LOG_DROP          0x00000080
#define LOG_DUMP          0x00000100
#define LOG_ERROR         0x00000400
#define LOG_PEER_ADDRS    0x00000800

static struct flagstr log_event_table[]={
    { "unexpected", LOG_UNEXPECTED },
    { "setup-init", LOG_SETUP_INIT },
    { "setup-timeout", LOG_SETUP_TIMEOUT },
    { "activate-key", LOG_ACTIVATE_KEY },
    { "timeout-key", LOG_TIMEOUT_KEY },
    { "security", LOG_SEC },
    { "state-change", LOG_STATE },
    { "packet-drop", LOG_DROP },
    { "dump-packets", LOG_DUMP },
    { "errors", LOG_ERROR },
    { "peer-addrs", LOG_PEER_ADDRS },
    { "default", LOG_SETUP_INIT|LOG_SETUP_TIMEOUT|
      LOG_ACTIVATE_KEY|LOG_TIMEOUT_KEY|LOG_SEC|LOG_ERROR },
    { "all", 0xffffffff },
    { NULL, 0 }
};


/***** TRANSPORT PEERS declarations *****/

/* Details of "mobile peer" semantics:

   - We use the same data structure for the different configurations,
     but manage it with different algorithms.
   
   - We record up to mobile_peers_max peer address/port numbers
     ("peers") for key setup, and separately up to mobile_peers_max
     for data transfer.

   - In general, we make a new set of addrs (see below) when we start
     a new key exchange; the key setup addrs become the data transport
     addrs when key setup complets.

   If our peer is mobile:

   - We send to all recent addresses of incoming packets, plus
     initially all configured addresses (which we also expire).

   - So, we record addrs of good incoming packets, as follows:
      1. expire any peers last seen >120s ("mobile-peer-expiry") ago
      2. add the peer of the just received packet to the applicable list
         (possibly evicting the oldest entries to make room)
     NB that we do not expire peers until an incoming packet arrives.

   - If the peer has a configured address or name, we record them the
     same way, but only as a result of our own initiation of key
     setup.  (We might evict some incoming packet addrs to make room.)

   - The default number of addrs to keep is 3, or 4 if we have a
     configured name or address.  That's space for two configured
     addresses (one IPv6 and one IPv4), plus two received addresses.

   - Outgoing packets are sent to every recorded address in the
     applicable list.  Any unsupported[1] addresses are deleted from
     the list right away.  (This should only happen to configured
     addresses, of course, but there is no need to check that.)

   - When we successfully complete a key setup, we merge the key setup
     peers into the data transfer peers.

   [1] An unsupported address is one for whose AF we don't have a
     socket (perhaps because we got EAFNOSUPPORT or some such) or for
     which sendto gives ENETUNREACH.

   If neither end is mobile:

   - When peer initiated the key exchange, we use the incoming packet
     address.

   - When we initiate the key exchange, we try configured addresses
     until we get one which isn't unsupported then fixate on that.

   - When we complete a key setup, we replace the data transport peers
     with those from the key setup.

   If we are mobile:

   - We can't tell when local network setup changes so we can't cache
     the unsupported addrs and completely remove the spurious calls to
     sendto, but we can optimise things a bit by deprioritising addrs
     which seem to be unsupported.

   - Use only configured addresses.  (Except, that if our peer
     initiated a key exchange we use the incoming packet address until
     our name resolution completes.)

   - When we send a packet, try each address in turn; if addr
     supported, put that address to the end of the list for future
     packets, and go onto the next address.

   - When we complete a key setup, we replace the data transport peers
     with those from the key setup.

   */

typedef struct {
    struct timeval last;
    struct comm_addr addr;
} transport_peer;

typedef struct {
/* configuration information */
/* runtime information */
    int npeers;
    transport_peer peers[MAX_PEER_ADDRS];
} transport_peers;

/* Basic operations on transport peer address sets */
static void transport_peers_clear(struct site *st, transport_peers *peers);
static int transport_peers_valid(transport_peers *peers);
static void transport_peers_copy(struct site *st, transport_peers *dst,
				 const transport_peers *src);

/* Record address of incoming setup packet; resp. data packet. */
static void transport_setup_msgok(struct site *st, const struct comm_addr *a);
static void transport_data_msgok(struct site *st, const struct comm_addr *a);

/* Initialise the setup addresses.  Called before we send the first
 * packet in a key exchange.  If we are the initiator, as a result of
 * resolve completing (or being determined not to be relevant) or an
 * incoming PROD; if we are the responder, as a result of the MSG1. */
static bool_t transport_compute_setupinit_peers(struct site *st,
        const struct comm_addr *configured_addrs /* 0 if none or not found */,
        int n_configured_addrs /* 0 if none or not found */,
        const struct comm_addr *incoming_packet_addr /* 0 if none */);

/* Called if we are the responder in a key setup, when the resolve
 * completes.  transport_compute_setupinit_peers will hvae been called
 * earlier.  If _complete is called, we are still doing the key setup
 * (and we should use the new values for both the rest of the key
 * setup and the ongoing data exchange); if _tardy is called, the key
 * setup is done (either completed or not) and only the data peers are
 * relevant */
static void transport_resolve_complete(struct site *st,
        const struct comm_addr *addrs, int naddrs);
static void transport_resolve_complete_tardy(struct site *st,
        const struct comm_addr *addrs, int naddrs);

static void transport_xmit(struct site *st, transport_peers *peers,
			   struct buffer_if *buf, bool_t candebug);

 /***** END of transport peers declarations *****/


struct data_key {
    struct transform_inst_if *transform;
    uint64_t key_timeout; /* End of life of current key */
    uint32_t remote_session_id;
};

struct site {
    closure_t cl;
    struct site_if ops;
/* configuration information */
    string_t localname;
    string_t remotename;
    bool_t keepalive;
    bool_t local_mobile, peer_mobile; /* Mobile client support */
    int32_t transport_peers_max;
    string_t tunname; /* localname<->remotename by default, used in logs */
    cstring_t *addresses; /* DNS name or address(es) for bootstrapping, optional */
    int remoteport; /* Port for bootstrapping, optional */
    uint32_t mtu_target;
    struct netlink_if *netlink;
    struct comm_if **comms;
    struct comm_clientinfo **commclientinfos;
    int ncomms;
    struct resolver_if *resolver;
    struct log_if *log;
    struct random_if *random;
    struct sigprivkey_if *privkey;
    struct sigpubkey_if *pubkey;
    struct transform_if **transforms;
    int ntransforms;
    struct dh_if *dh;

    uint32_t index; /* Index of this site */
    uint32_t early_capabilities;
    uint32_t local_capabilities;
    int32_t setup_retries; /* How many times to send setup packets */
    int32_t setup_retry_interval; /* Initial timeout for setup packets */
    int32_t wait_timeout_mean; /* How long to wait if setup unsuccessful */
    int32_t mobile_peer_expiry; /* How long to remember 2ary addresses */
    int32_t key_lifetime; /* How long a key lasts once set up */
    int32_t key_renegotiate_time; /* If we see traffic (or a keepalive)
				      after this time, initiate a new
				      key exchange */

    bool_t our_name_later; /* our name > peer name */
    uint32_t log_events;

/* runtime information */
    uint32_t state;
    uint64_t now; /* Most recently seen time */
    bool_t allow_send_prod;
    bool_t msg1_crossed_logged;
    int resolving_count;
    int resolving_n_results_all;
    int resolving_n_results_stored;
    struct comm_addr resolving_results[MAX_PEER_ADDRS];

    /* The currently established session */
    struct data_key current;
    struct data_key auxiliary_key;
    bool_t auxiliary_is_new;
    uint64_t renegotiate_key_time; /* When we can negotiate a new key */
    uint64_t auxiliary_renegotiate_key_time;
    transport_peers peers; /* Current address(es) of peer for data traffic */

    /* The current key setup protocol exchange.  We can only be
       involved in one of these at a time.  There's a potential for
       denial of service here (the attacker keeps sending a setup
       packet; we keep trying to continue the exchange, and have to
       timeout before we can listen for another setup packet); perhaps
       we should keep a list of 'bad' sources for setup packets. */
    uint32_t remote_capabilities;
    uint16_t remote_adv_mtu;
    struct transform_if *chosen_transform;
    uint32_t setup_session_id;
    transport_peers setup_peers;
    uint8_t localN[NONCELEN]; /* Nonces for key exchange */
    uint8_t remoteN[NONCELEN];
    struct buffer_if buffer; /* Current outgoing key exchange packet */
    struct buffer_if scratch;
    int32_t retries; /* Number of retries remaining */
    uint64_t timeout; /* Timeout for current state */
    uint8_t *dhsecret;
    uint8_t *sharedsecret;
    uint32_t sharedsecretlen, sharedsecretallocd;
    struct transform_inst_if *new_transform; /* For key setup/verify */
};

static uint32_t event_log_priority(struct site *st, uint32_t event)
{
    if (!(event&st->log_events))
	return 0;
    switch(event) {
    case LOG_UNEXPECTED:    return M_INFO;
    case LOG_SETUP_INIT:    return M_INFO;
    case LOG_SETUP_TIMEOUT: return M_NOTICE;
    case LOG_ACTIVATE_KEY:  return M_INFO;
    case LOG_TIMEOUT_KEY:   return M_INFO;
    case LOG_SEC:           return M_SECURITY;
    case LOG_STATE:         return M_DEBUG;
    case LOG_DROP:          return M_DEBUG;
    case LOG_DUMP:          return M_DEBUG;
    case LOG_ERROR:         return M_ERR;
    case LOG_PEER_ADDRS:    return M_DEBUG;
    default:                return M_ERR;
    }
}

static uint32_t slog_start(struct site *st, uint32_t event)
{
    uint32_t class=event_log_priority(st, event);
    if (class) {
	slilog_part(st->log,class,"%s: ",st->tunname);
    }
    return class;
}

static void vslog(struct site *st, uint32_t event, cstring_t msg, va_list ap)
FORMAT(printf,3,0);
static void vslog(struct site *st, uint32_t event, cstring_t msg, va_list ap)
{
    uint32_t class;

    class=slog_start(st,event);
    if (class) {
	vslilog_part(st->log,class,msg,ap);
	slilog_part(st->log,class,"\n");
    }
}

static void slog(struct site *st, uint32_t event, cstring_t msg, ...)
FORMAT(printf,3,4);
static void slog(struct site *st, uint32_t event, cstring_t msg, ...)
{
    va_list ap;
    va_start(ap,msg);
    vslog(st,event,msg,ap);
    va_end(ap);
}

static void logtimeout(struct site *st, const char *fmt, ...)
FORMAT(printf,2,3);
static void logtimeout(struct site *st, const char *fmt, ...)
{
    uint32_t class=event_log_priority(st,LOG_SETUP_TIMEOUT);
    if (!class)
	return;

    va_list ap;
    va_start(ap,fmt);

    slilog_part(st->log,class,"%s: ",st->tunname);
    vslilog_part(st->log,class,fmt,ap);

    const char *delim;
    int i;
    for (i=0, delim=" (tried ";
	 i<st->setup_peers.npeers;
	 i++, delim=", ") {
	transport_peer *peer=&st->setup_peers.peers[i];
	const char *s=comm_addr_to_string(&peer->addr);
	slilog_part(st->log,class,"%s%s",delim,s);
    }

    slilog_part(st->log,class,")\n");
    va_end(ap);
}

static void set_link_quality(struct site *st);
static void delete_keys(struct site *st, cstring_t reason, uint32_t loglevel);
static void delete_one_key(struct site *st, struct data_key *key,
			   const char *reason /* may be 0 meaning don't log*/,
			   const char *which /* ignored if !reasonn */,
			   uint32_t loglevel /* ignored if !reasonn */);
static bool_t initiate_key_setup(struct site *st, cstring_t reason,
				 const struct comm_addr *prod_hint);
static void enter_state_run(struct site *st);
static bool_t enter_state_resolve(struct site *st);
static void decrement_resolving_count(struct site *st, int by);
static bool_t enter_new_state(struct site *st,uint32_t next,
			      const struct msg *prompt
			      /* may be 0 for SENTMSG1 */);
static void enter_state_wait(struct site *st);
static void activate_new_key(struct site *st);

static bool_t is_transform_valid(struct transform_inst_if *transform)
{
    return transform && transform->valid(transform->st);
}

static bool_t current_valid(struct site *st)
{
    return is_transform_valid(st->current.transform);
}

#define DEFINE_CALL_TRANSFORM(fwdrev)					\
static transform_apply_return                                           \
call_transform_##fwdrev(struct site *st,				\
				   struct transform_inst_if *transform,	\
				   struct buffer_if *buf,		\
				   const char **errmsg)			\
{									\
    if (!is_transform_valid(transform)) {				\
	*errmsg="transform not set up";					\
	return transform_apply_err;					\
    }									\
    return transform->fwdrev(transform->st,buf,errmsg);			\
}

DEFINE_CALL_TRANSFORM(forwards)
DEFINE_CALL_TRANSFORM(reverse)

static void dispose_transform(struct transform_inst_if **transform_var)
{
    struct transform_inst_if *transform=*transform_var;
    if (transform) {
	transform->delkey(transform->st);
	transform->destroy(transform->st);
    }
    *transform_var = 0;
}    

#define CHECK_AVAIL(b,l) do { if ((b)->size<(l)) return False; } while(0)
#define CHECK_EMPTY(b) do { if ((b)->size!=0) return False; } while(0)
#define CHECK_TYPE(b,t) do { uint32_t type; \
    CHECK_AVAIL((b),4); \
    type=buf_unprepend_uint32((b)); \
    if (type!=(t)) return False; } while(0)

static _Bool type_is_msg34(uint32_t type)
{
    switch (type) {
	case CASES_MSG3_KNOWN: case LABEL_MSG4: return True;
	default: return False;
    }
}

struct parsedname {
    int32_t len;
    uint8_t *name;
    struct buffer_if extrainfo;
};

struct msg {
    uint8_t *hashstart;
    uint32_t dest;
    uint32_t source;
    struct parsedname remote;
    struct parsedname local;
    uint32_t remote_capabilities;
    uint16_t remote_mtu;
    int capab_transformnum;
    uint8_t *nR;
    uint8_t *nL;
    int32_t pklen;
    char *pk;
    int32_t hashlen;
    struct alg_msg_data sig;
};

static int32_t wait_timeout(struct site *st) {
    int32_t t = st->wait_timeout_mean;
    int8_t factor;
    if (t < INT_MAX/2) {
	st->random->generate(st->random->st,sizeof(factor),&factor);
	t += (t / 256) * factor;
    }
    return t;
}

static _Bool set_new_transform(struct site *st, char *pk)
{
    _Bool ok;

    /* Make room for the shared key */
    st->sharedsecretlen=st->chosen_transform->keylen?:st->dh->ceil_len;
    assert(st->sharedsecretlen);
    if (st->sharedsecretlen > st->sharedsecretallocd) {
	st->sharedsecretallocd=st->sharedsecretlen;
	st->sharedsecret=safe_realloc_ary(st->sharedsecret,1,
					  st->sharedsecretallocd,
					  "site:sharedsecret");
    }

    /* Generate the shared key */
    st->dh->makeshared(st->dh->st,st->dhsecret,st->dh->len,pk,
		       st->sharedsecret,st->sharedsecretlen);

    /* Set up the transform */
    struct transform_if *generator=st->chosen_transform;
    struct transform_inst_if *generated=generator->create(generator->st);
    ok = generated->setkey(generated->st,st->sharedsecret,
			   st->sharedsecretlen,st->our_name_later);

    dispose_transform(&st->new_transform);
    if (!ok) return False;
    st->new_transform=generated;

    slog(st,LOG_SETUP_INIT,"key exchange negotiated transform"
	 " %d (capabilities ours=%#"PRIx32" theirs=%#"PRIx32")",
	 st->chosen_transform->capab_bit,
	 st->local_capabilities, st->remote_capabilities);
    return True;
}

struct xinfoadd {
    int32_t lenpos, afternul;
};
static void append_string_xinfo_start(struct buffer_if *buf,
				      struct xinfoadd *xia,
				      const char *str)
    /* Helps construct one of the names with additional info as found
     * in MSG1..4.  Call this function first, then append all the
     * desired extra info (not including the nul byte) to the buffer,
     * then call append_string_xinfo_done. */
{
    xia->lenpos = buf->size;
    buf_append_string(buf,str);
    buf_append_uint8(buf,0);
    xia->afternul = buf->size;
}
static void append_string_xinfo_done(struct buffer_if *buf,
				     struct xinfoadd *xia)
{
    /* we just need to adjust the string length */
    if (buf->size == xia->afternul) {
	/* no extra info, strip the nul too */
	buf_unappend_uint8(buf);
    } else {
	put_uint16(buf->start+xia->lenpos, buf->size-(xia->lenpos+2));
    }
}

/* Build any of msg1 to msg4. msg5 and msg6 are built from the inside
   out using a transform of config data supplied by netlink */
static bool_t generate_msg(struct site *st, uint32_t type, cstring_t what,
			   const struct msg *prompt
			   /* may be 0 for MSG1 */)
{
    string_t dhpub;
    unsigned minor;

    st->retries=st->setup_retries;
    BUF_ALLOC(&st->buffer,what);
    buffer_init(&st->buffer,0);
    buf_append_uint32(&st->buffer,
	(type==LABEL_MSG1?0:st->setup_session_id));
    buf_append_uint32(&st->buffer,st->index);
    buf_append_uint32(&st->buffer,type);

    struct xinfoadd xia;
    append_string_xinfo_start(&st->buffer,&xia,st->localname);
    if ((st->local_capabilities & st->early_capabilities) ||
	(type != LABEL_MSG1)) {
	buf_append_uint32(&st->buffer,st->local_capabilities);
    }
    if (type_is_msg34(type)) {
	buf_append_uint16(&st->buffer,st->mtu_target);
    }
    append_string_xinfo_done(&st->buffer,&xia);

    buf_append_string(&st->buffer,st->remotename);
    BUF_ADD_OBJ(append,&st->buffer,st->localN);
    if (type==LABEL_MSG1) return True;
    BUF_ADD_OBJ(append,&st->buffer,st->remoteN);
    if (type==LABEL_MSG2) return True;

    if (hacky_par_mid_failnow()) return False;

    if (MSGMAJOR(type) == 3) do {
	minor = MSGMINOR(type);
	if (minor < 1) break;
	buf_append_uint8(&st->buffer,st->chosen_transform->capab_bit);
    } while (0);

    dhpub=st->dh->makepublic(st->dh->st,st->dhsecret,st->dh->len);
    buf_append_string(&st->buffer,dhpub);
    free(dhpub);

    bool_t ok=st->privkey->sign(st->privkey->st,
				st->buffer.start,
				st->buffer.size,
				&st->buffer);
    if (!ok) goto fail;
    return True;

 fail:
    return False;
}

static bool_t unpick_name(struct buffer_if *msg, struct parsedname *nm)
{
    CHECK_AVAIL(msg,2);
    nm->len=buf_unprepend_uint16(msg);
    CHECK_AVAIL(msg,nm->len);
    nm->name=buf_unprepend(msg,nm->len);
    uint8_t *nul=memchr(nm->name,0,nm->len);
    if (!nul) {
	buffer_readonly_view(&nm->extrainfo,0,0);
    } else {
	buffer_readonly_view(&nm->extrainfo, nul+1, msg->start-(nul+1));
	nm->len=nul-nm->name;
    }
    return True;
}

static bool_t unpick_msg(struct site *st, uint32_t type,
			 struct buffer_if *msg, struct msg *m)
{
    unsigned minor;

    m->capab_transformnum=-1;
    m->hashstart=msg->start;
    CHECK_AVAIL(msg,4);
    m->dest=buf_unprepend_uint32(msg);
    CHECK_AVAIL(msg,4);
    m->source=buf_unprepend_uint32(msg);
    CHECK_TYPE(msg,type);
    if (!unpick_name(msg,&m->remote)) return False;
    m->remote_capabilities=0;
    m->remote_mtu=0;
    if (m->remote.extrainfo.size) {
	CHECK_AVAIL(&m->remote.extrainfo,4);
	m->remote_capabilities=buf_unprepend_uint32(&m->remote.extrainfo);
    }
    if (type_is_msg34(type) && m->remote.extrainfo.size) {
	CHECK_AVAIL(&m->remote.extrainfo,2);
	m->remote_mtu=buf_unprepend_uint16(&m->remote.extrainfo);
    }
    if (!unpick_name(msg,&m->local)) return False;
    if (type==LABEL_PROD) {
	CHECK_EMPTY(msg);
	return True;
    }
    CHECK_AVAIL(msg,NONCELEN);
    m->nR=buf_unprepend(msg,NONCELEN);
    if (type==LABEL_MSG1) {
	CHECK_EMPTY(msg);
	return True;
    }
    CHECK_AVAIL(msg,NONCELEN);
    m->nL=buf_unprepend(msg,NONCELEN);
    if (type==LABEL_MSG2) {
	CHECK_EMPTY(msg);
	return True;
    }
    if (MSGMAJOR(type) == 3) do {
	minor = MSGMINOR(type);
#define MAYBE_READ_CAP(minminor, kind, dflt) do {			\
    if (minor < (minminor))						\
	m->capab_##kind##num = (dflt);					\
    else {								\
	CHECK_AVAIL(msg, 1);						\
	m->capab_##kind##num = buf_unprepend_uint8(msg);		\
    }									\
} while (0)
	MAYBE_READ_CAP(1, transform, CAPAB_BIT_ANCIENTTRANSFORM);
#undef MAYBE_READ_CAP
    } while (0);
    CHECK_AVAIL(msg,2);
    m->pklen=buf_unprepend_uint16(msg);
    CHECK_AVAIL(msg,m->pklen);
    m->pk=buf_unprepend(msg,m->pklen);
    m->hashlen=msg->start-m->hashstart;

    if (!st->pubkey->unpick(st->pubkey->st,msg,&m->sig)) {
	return False;
    }

    CHECK_EMPTY(msg);

    return True;
}

static bool_t name_matches(const struct parsedname *nm, const char *expected)
{
    int expected_len=strlen(expected);
    return
	nm->len == expected_len &&
	!memcmp(nm->name, expected, expected_len);
}    

static bool_t check_msg(struct site *st, uint32_t type, struct msg *m,
			cstring_t *error)
{
    if (type==LABEL_MSG1) return True;

    /* Check that the site names and our nonce have been sent
       back correctly, and then store our peer's nonce. */ 
    if (!name_matches(&m->remote,st->remotename)) {
	*error="wrong remote site name";
	return False;
    }
    if (!name_matches(&m->local,st->localname)) {
	*error="wrong local site name";
	return False;
    }
    if (memcmp(m->nL,st->localN,NONCELEN)!=0) {
	*error="wrong locally-generated nonce";
	return False;
    }
    if (type==LABEL_MSG2) return True;
    if (!consttime_memeq(m->nR,st->remoteN,NONCELEN)) {
	*error="wrong remotely-generated nonce";
	return False;
    }
    /* MSG3 has complicated rules about capabilities, which are
     * handled in process_msg3. */
    if (MSGMAJOR(type) == 3) return True;
    if (m->remote_capabilities!=st->remote_capabilities) {
	*error="remote capabilities changed";
	return False;
    }
    if (type==LABEL_MSG4) return True;
    *error="unknown message type";
    return False;
}

static bool_t kex_init(struct site *st)
{
    st->random->generate(st->random->st,NONCELEN,st->localN);
    return True;
}

static bool_t generate_msg1(struct site *st, const struct msg *prompt_maybe_0)
{
    return
	generate_msg(st,LABEL_MSG1,"site:MSG1",prompt_maybe_0);
}

static bool_t process_msg1(struct site *st, struct buffer_if *msg1,
			   const struct comm_addr *src,
			   const struct msg *m)
{
    /* We've already determined we're in an appropriate state to
       process an incoming MSG1, and that the MSG1 has correct values
       of A and B. */

    st->setup_session_id=m->source;
    st->remote_capabilities=m->remote_capabilities;
    memcpy(st->remoteN,m->nR,NONCELEN);
    return True;
}

static bool_t generate_msg2(struct site *st,
			    const struct msg *prompt_may_be_null)
{
    return
	generate_msg(st,LABEL_MSG2,"site:MSG2",prompt_may_be_null);
}

static bool_t process_msg2(struct site *st, struct buffer_if *msg2,
			   const struct comm_addr *src,
			   struct msg *m /* returned */)
{
    cstring_t err;

    if (!unpick_msg(st,LABEL_MSG2,msg2,m)) return False;
    if (!check_msg(st,LABEL_MSG2,m,&err)) {
	slog(st,LOG_SEC,"msg2: %s",err);
	return False;
    }
    st->setup_session_id=m->source;
    st->remote_capabilities=m->remote_capabilities;

    /* Select the transform to use */

    uint32_t remote_crypto_caps = st->remote_capabilities & CAPAB_TRANSFORM_MASK;
    if (!remote_crypto_caps)
	/* old secnets only had this one transform */
	remote_crypto_caps = 1UL << CAPAB_BIT_ANCIENTTRANSFORM;

#define CHOOSE_CRYPTO(kind, whats) do {					\
    struct kind##_if *iface;						\
    uint32_t bit, ours = 0;						\
    int i;								\
    for (i= 0; i < st->n##kind##s; i++) {				\
	iface=st->kind##s[i];						\
	bit = 1UL << iface->capab_bit;					\
	if (bit & remote_crypto_caps) goto kind##_found;		\
	ours |= bit;							\
    }									\
    slog(st,LOG_ERROR,"no " whats " in common"				\
	 " (us %#"PRIx32"; them: %#"PRIx32")",				\
	 st->local_capabilities & ours, remote_crypto_caps);		\
    return False;							\
kind##_found:								\
    st->chosen_##kind = iface;						\
} while (0)

    CHOOSE_CRYPTO(transform, "transforms");

#undef CHOOSE_CRYPTO

    memcpy(st->remoteN,m->nR,NONCELEN);
    return True;
}

static bool_t generate_msg3(struct site *st, const struct msg *prompt)
{
    /* Now we have our nonce and their nonce. Think of a secret key,
       and create message number 3. */
    st->random->generate(st->random->st,st->dh->len,st->dhsecret);
    return generate_msg(st,
			(st->remote_capabilities & CAPAB_TRANSFORM_MASK)
			? LABEL_MSG3BIS
			: LABEL_MSG3,
			"site:MSG3",prompt);
}

static bool_t process_msg3_msg4(struct site *st, struct msg *m)
{
    /* Check signature and store g^x mod m */
    if (!st->pubkey->check(st->pubkey->st,
			   m->hashstart,m->hashlen,
			   &m->sig)) {
	slog(st,LOG_SEC,"msg3/msg4 signature failed check!");
	return False;
    }

    st->remote_adv_mtu=m->remote_mtu;

    return True;
}

static bool_t process_msg3(struct site *st, struct buffer_if *msg3,
			   const struct comm_addr *src, uint32_t msgtype,
			   struct msg *m /* returned */)
{
    cstring_t err;

    switch (msgtype) {
	case CASES_MSG3_KNOWN: break;
	default: assert(0);
    }

    if (!unpick_msg(st,msgtype,msg3,m)) return False;
    if (!check_msg(st,msgtype,m,&err)) {
	slog(st,LOG_SEC,"msg3: %s",err);
	return False;
    }
    uint32_t capab_adv_late = m->remote_capabilities
	& ~st->remote_capabilities & st->early_capabilities;
    if (capab_adv_late) {
	slog(st,LOG_SEC,"msg3 impermissibly adds early capability flag(s)"
	     " %#"PRIx32" (was %#"PRIx32", now %#"PRIx32")",
	     capab_adv_late, st->remote_capabilities, m->remote_capabilities);
	return False;
    }

#define CHOSE_CRYPTO(kind, what) do {					\
    struct kind##_if *iface;						\
    int i;								\
    for (i=0; i<st->n##kind##s; i++) {					\
	iface=st->kind##s[i];						\
	if (iface->capab_bit == m->capab_##kind##num)			\
	    goto kind##_found;						\
    }									\
    slog(st,LOG_SEC,"peer chose unknown-to-us " what " %d!",		\
	 m->capab_##kind##num);							\
    return False;							\
kind##_found:								\
    st->chosen_##kind=iface;						\
} while (0)

    CHOSE_CRYPTO(transform, "transform");

#undef CHOSE_CRYPTO

    if (!process_msg3_msg4(st,m))
	return False;

    /* Update our idea of the remote site's capabilities, now that we've
     * verified that its message was authentic.
     *
     * Our previous idea of the remote site's capabilities came from the
     * unauthenticated MSG1.  We've already checked that this new message
     * doesn't change any of the bits we relied upon in the past, but it may
     * also have set additional capability bits.  We simply throw those away
     * now, and use the authentic capabilities from this MSG3. */
    st->remote_capabilities=m->remote_capabilities;

    /* Terminate their DH public key with a '0' */
    m->pk[m->pklen]=0;
    /* Invent our DH secret key */
    st->random->generate(st->random->st,st->dh->len,st->dhsecret);

    /* Generate the shared key and set up the transform */
    if (!set_new_transform(st,m->pk)) return False;

    return True;
}

static bool_t generate_msg4(struct site *st, const struct msg *prompt)
{
    /* We have both nonces, their public key and our private key. Generate
       our public key, sign it and send it to them. */
    return generate_msg(st,LABEL_MSG4,"site:MSG4",prompt);
}

static bool_t process_msg4(struct site *st, struct buffer_if *msg4,
			   const struct comm_addr *src,
			   struct msg *m /* returned */)
{
    cstring_t err;

    if (!unpick_msg(st,LABEL_MSG4,msg4,m)) return False;
    if (!check_msg(st,LABEL_MSG4,m,&err)) {
	slog(st,LOG_SEC,"msg4: %s",err);
	return False;
    }
    
    if (!process_msg3_msg4(st,m))
	return False;

    /* Terminate their DH public key with a '0' */
    m->pk[m->pklen]=0;

    /* Generate the shared key and set up the transform */
    if (!set_new_transform(st,m->pk)) return False;

    return True;
}

struct msg0 {
    uint32_t dest;
    uint32_t source;
    uint32_t type;
};

static bool_t unpick_msg0(struct site *st, struct buffer_if *msg0,
			  struct msg0 *m)
{
    CHECK_AVAIL(msg0,4);
    m->dest=buf_unprepend_uint32(msg0);
    CHECK_AVAIL(msg0,4);
    m->source=buf_unprepend_uint32(msg0);
    CHECK_AVAIL(msg0,4);
    m->type=buf_unprepend_uint32(msg0);
    return True;
    /* Leaves transformed part of buffer untouched */
}

static bool_t generate_msg5(struct site *st, const struct msg *prompt)
{
    cstring_t transform_err;

    BUF_ALLOC(&st->buffer,"site:MSG5");
    /* We are going to add four words to the message */
    buffer_init(&st->buffer,calculate_max_start_pad());
    /* Give the netlink code an opportunity to put its own stuff in the
       message (configuration information, etc.) */
    buf_prepend_uint32(&st->buffer,LABEL_MSG5);
    if (call_transform_forwards(st,st->new_transform,
				&st->buffer,&transform_err))
	return False;
    buf_prepend_uint32(&st->buffer,LABEL_MSG5);
    buf_prepend_uint32(&st->buffer,st->index);
    buf_prepend_uint32(&st->buffer,st->setup_session_id);

    st->retries=st->setup_retries;
    return True;
}

static bool_t process_msg5(struct site *st, struct buffer_if *msg5,
			   const struct comm_addr *src,
			   struct transform_inst_if *transform)
{
    struct msg0 m;
    cstring_t transform_err;

    if (!unpick_msg0(st,msg5,&m)) return False;

    if (call_transform_reverse(st,transform,msg5,&transform_err)) {
	/* There's a problem */
	slog(st,LOG_SEC,"process_msg5: transform: %s",transform_err);
	return False;
    }
    /* Buffer should now contain untransformed PING packet data */
    CHECK_AVAIL(msg5,4);
    if (buf_unprepend_uint32(msg5)!=LABEL_MSG5) {
	slog(st,LOG_SEC,"MSG5/PING packet contained wrong label");
	return False;
    }
    /* Older versions of secnet used to write some config data here
     * which we ignore.  So we don't CHECK_EMPTY */
    return True;
}

static void create_msg6(struct site *st, struct transform_inst_if *transform,
			uint32_t session_id)
{
    cstring_t transform_err;

    BUF_ALLOC(&st->buffer,"site:MSG6");
    /* We are going to add four words to the message */
    buffer_init(&st->buffer,calculate_max_start_pad());
    /* Give the netlink code an opportunity to put its own stuff in the
       message (configuration information, etc.) */
    buf_prepend_uint32(&st->buffer,LABEL_MSG6);
    transform_apply_return problem =
	call_transform_forwards(st,transform,
				&st->buffer,&transform_err);
    assert(!problem);
    buf_prepend_uint32(&st->buffer,LABEL_MSG6);
    buf_prepend_uint32(&st->buffer,st->index);
    buf_prepend_uint32(&st->buffer,session_id);
}

static bool_t generate_msg6(struct site *st, const struct msg *prompt)
{
    if (!is_transform_valid(st->new_transform))
	return False;
    create_msg6(st,st->new_transform,st->setup_session_id);
    st->retries=1; /* Peer will retransmit MSG5 if this packet gets lost */
    return True;
}

static bool_t process_msg6(struct site *st, struct buffer_if *msg6,
			   const struct comm_addr *src)
{
    struct msg0 m;
    cstring_t transform_err;

    if (!unpick_msg0(st,msg6,&m)) return False;

    if (call_transform_reverse(st,st->new_transform,msg6,&transform_err)) {
	/* There's a problem */
	slog(st,LOG_SEC,"process_msg6: transform: %s",transform_err);
	return False;
    }
    /* Buffer should now contain untransformed PING packet data */
    CHECK_AVAIL(msg6,4);
    if (buf_unprepend_uint32(msg6)!=LABEL_MSG6) {
	slog(st,LOG_SEC,"MSG6/PONG packet contained invalid data");
	return False;
    }
    /* Older versions of secnet used to write some config data here
     * which we ignore.  So we don't CHECK_EMPTY */
    return True;
}

static transform_apply_return
decrypt_msg0(struct site *st, struct buffer_if *msg0,
			   const struct comm_addr *src)
{
    cstring_t transform_err, auxkey_err, newkey_err="n/a";
    struct msg0 m;
    transform_apply_return problem;

    if (!unpick_msg0(st,msg0,&m)) return False;

    /* Keep a copy so we can try decrypting it with multiple keys */
    buffer_copy(&st->scratch, msg0);

    problem = call_transform_reverse(st,st->current.transform,
				     msg0,&transform_err);
    if (!problem) {
	if (!st->auxiliary_is_new)
	    delete_one_key(st,&st->auxiliary_key,
			   "peer has used new key","auxiliary key",LOG_SEC);
	return 0;
    }
    if (transform_apply_return_badseq(problem))
	goto badseq;

    buffer_copy(msg0, &st->scratch);
    problem = call_transform_reverse(st,st->auxiliary_key.transform,
				     msg0,&auxkey_err);
    if (!problem) {
	slog(st,LOG_DROP,"processing packet which uses auxiliary key");
	if (st->auxiliary_is_new) {
	    /* We previously timed out in state SENTMSG5 but it turns
	     * out that our peer did in fact get our MSG5 and is
	     * using the new key.  So we should switch to it too. */
	    /* This is a bit like activate_new_key. */
	    struct data_key t;
	    t=st->current;
	    st->current=st->auxiliary_key;
	    st->auxiliary_key=t;

	    delete_one_key(st,&st->auxiliary_key,"peer has used new key",
			   "previous key",LOG_SEC);
	    st->auxiliary_is_new=0;
	    st->renegotiate_key_time=st->auxiliary_renegotiate_key_time;
	}
	return 0;
    }
    if (transform_apply_return_badseq(problem))
	goto badseq;

    if (st->state==SITE_SENTMSG5) {
	buffer_copy(msg0, &st->scratch);
	problem = call_transform_reverse(st,st->new_transform,
					 msg0,&newkey_err);
	if (!problem) {
	    /* It looks like we didn't get the peer's MSG6 */
	    /* This is like a cut-down enter_new_state(SITE_RUN) */
	    slog(st,LOG_STATE,"will enter state RUN (MSG0 with new key)");
	    BUF_FREE(&st->buffer);
	    st->timeout=0;
	    activate_new_key(st);
	    return 0; /* do process the data in this packet */
	}
	if (transform_apply_return_badseq(problem))
	    goto badseq;
    }

    slog(st,LOG_SEC,"transform: %s (aux: %s, new: %s)",
	 transform_err,auxkey_err,newkey_err);
    initiate_key_setup(st,"incoming message would not decrypt",0);
    send_nak(src,m.dest,m.source,m.type,msg0,"message would not decrypt");
    assert(problem);
    return problem;

 badseq:
    slog(st,LOG_DROP,"transform: %s (bad seq.)",transform_err);
    assert(problem);
    return problem;
}

static bool_t process_msg0(struct site *st, struct buffer_if *msg0,
			   const struct comm_addr *src)
{
    uint32_t type;
    transform_apply_return problem;

    problem = decrypt_msg0(st,msg0,src);
    if (problem==transform_apply_seqdupe) {
	/* We recently received another copy of this packet, maybe due
	 * to polypath.  That's not a problem; indeed, for the
	 * purposes of transport address management it is a success.
	 * But we don't want to process the packet. */
	transport_data_msgok(st,src);
	return False;
    }
    if (problem)
	return False;

    CHECK_AVAIL(msg0,4);
    type=buf_unprepend_uint32(msg0);
    switch(type) {
    case LABEL_MSG7:
	/* We must forget about the current session. */
	delete_keys(st,"request from peer",LOG_SEC);
	/* probably, the peer is shutting down, and this is going to fail,
	 * but we need to be trying to bring the link up again */
	if (st->keepalive)
	    initiate_key_setup(st,"peer requested key teardown",0);
	return True;
    case LABEL_MSG9:
	/* Deliver to netlink layer */
	st->netlink->deliver(st->netlink->st,msg0);
	transport_data_msgok(st,src);
	/* See whether we should start negotiating a new key */
	if (st->now > st->renegotiate_key_time)
	    initiate_key_setup(st,"incoming packet in renegotiation window",0);
	return True;
    default:
	slog(st,LOG_SEC,"incoming encrypted message of type %08x "
	     "(unknown)",type);
	break;
    }
    return False;
}

static void dump_packet(struct site *st, struct buffer_if *buf,
			const struct comm_addr *addr, bool_t incoming,
			bool_t ok)
{
    uint32_t dest=get_uint32(buf->start);
    uint32_t source=get_uint32(buf->start+4);
    uint32_t msgtype=get_uint32(buf->start+8);

    if (st->log_events & LOG_DUMP)
	slilog(st->log,M_DEBUG,"%s: %s: %08x<-%08x: %08x: %s%s",
	       st->tunname,incoming?"incoming":"outgoing",
	       dest,source,msgtype,comm_addr_to_string(addr),
	       ok?"":" - fail");
}

static bool_t comm_addr_sendmsg(struct site *st,
				const struct comm_addr *dest,
				struct buffer_if *buf)
{
    int i;
    struct comm_clientinfo *commclientinfo = 0;

    for (i=0; i < st->ncomms; i++) {
	if (st->comms[i] == dest->comm) {
	    commclientinfo = st->commclientinfos[i];
	    break;
	}
    }
    return dest->comm->sendmsg(dest->comm->st, buf, dest, commclientinfo);
}

static uint32_t site_status(void *st)
{
    return 0;
}

static bool_t send_msg(struct site *st)
{
    if (st->retries>0) {
	transport_xmit(st, &st->setup_peers, &st->buffer, True);
	st->timeout=st->now+st->setup_retry_interval;
	st->retries--;
	return True;
    } else if (st->state==SITE_SENTMSG5) {
	logtimeout(st,"timed out sending MSG5, stashing new key");
	/* We stash the key we have produced, in case it turns out that
	 * our peer did see our MSG5 after all and starts using it. */
	/* This is a bit like some of activate_new_key */
	struct transform_inst_if *t;
	t=st->auxiliary_key.transform;
	st->auxiliary_key.transform=st->new_transform;
	st->new_transform=t;
	dispose_transform(&st->new_transform);

	st->auxiliary_is_new=1;
	st->auxiliary_key.key_timeout=st->now+st->key_lifetime;
	st->auxiliary_renegotiate_key_time=st->now+st->key_renegotiate_time;
	st->auxiliary_key.remote_session_id=st->setup_session_id;

	enter_state_wait(st);
	return False;
    } else {
	logtimeout(st,"timed out sending key setup packet "
	    "(in state %s)",state_name(st->state));
	enter_state_wait(st);
	return False;
    }
}

static void site_resolve_callback(void *sst, const struct comm_addr *addrs,
				  int stored_naddrs, int all_naddrs,
				  const char *address, const char *failwhy)
{
    struct site *st=sst;

    if (!stored_naddrs) {
	slog(st,LOG_ERROR,"resolution of %s failed: %s",address,failwhy);
    } else {
	slog(st,LOG_PEER_ADDRS,"resolution of %s completed, %d addrs, eg: %s",
	     address, all_naddrs, comm_addr_to_string(&addrs[0]));;

	int space=st->transport_peers_max-st->resolving_n_results_stored;
	int n_tocopy=MIN(stored_naddrs,space);
	COPY_ARRAY(st->resolving_results + st->resolving_n_results_stored,
		   addrs,
		   n_tocopy);
	st->resolving_n_results_stored += n_tocopy;
	st->resolving_n_results_all += all_naddrs;
    }

    decrement_resolving_count(st,1);
}

static void decrement_resolving_count(struct site *st, int by)
{
    assert(st->resolving_count>0);
    st->resolving_count-=by;

    if (st->resolving_count)
	return;

    /* OK, we are done with them all.  Handle combined results. */

    const struct comm_addr *addrs=st->resolving_results;
    int naddrs=st->resolving_n_results_stored;
    assert(naddrs<=st->transport_peers_max);

    if (naddrs) {
 	if (naddrs != st->resolving_n_results_all) {
	    slog(st,LOG_SETUP_INIT,"resolution of supplied addresses/names"
		 " yielded too many results (%d > %d), some ignored",
		 st->resolving_n_results_all, naddrs);
	}
	slog(st,LOG_STATE,"resolution completed, %d addrs, eg: %s",
	     naddrs, iaddr_to_string(&addrs[0].ia));;
    }

    switch (st->state) {
    case SITE_RESOLVE:
        if (transport_compute_setupinit_peers(st,addrs,naddrs,0)) {
	    enter_new_state(st,SITE_SENTMSG1,0);
	} else {
	    /* Can't figure out who to try to to talk to */
	    slog(st,LOG_SETUP_INIT,
		 "key exchange failed: cannot find peer address");
	    enter_state_run(st);
	}
	break;
    case SITE_SENTMSG1: case SITE_SENTMSG2:
    case SITE_SENTMSG3: case SITE_SENTMSG4:
    case SITE_SENTMSG5:
	if (naddrs) {
	    /* We start using the address immediately for data too.
	     * It's best to store it in st->peers now because we might
	     * go via SENTMSG5, WAIT, and a MSG0, straight into using
	     * the new key (without updating the data peer addrs). */
	    transport_resolve_complete(st,addrs,naddrs);
	} else if (st->local_mobile) {
	    /* We can't let this rest because we may have a peer
	     * address which will break in the future. */
	    slog(st,LOG_SETUP_INIT,"resolution failed: "
		 "abandoning key exchange");
	    enter_state_wait(st);
	} else {
	    slog(st,LOG_SETUP_INIT,"resolution failed: "
		 " continuing to use source address of peer's packets"
		 " for key exchange and ultimately data");
	}
	break;
    case SITE_RUN:
	if (naddrs) {
	    slog(st,LOG_SETUP_INIT,"resolution completed tardily,"
		 " updating peer address(es)");
	    transport_resolve_complete_tardy(st,addrs,naddrs);
	} else if (st->local_mobile) {
	    /* Not very good.  We should queue (another) renegotiation
	     * so that we can update the peer address. */
	    st->key_renegotiate_time=st->now+wait_timeout(st);
	} else {
	    slog(st,LOG_SETUP_INIT,"resolution failed: "
		 " continuing to use source address of peer's packets");
	}
	break;
    case SITE_WAIT:
    case SITE_STOP:
	/* oh well */
	break;
    }
}

static bool_t initiate_key_setup(struct site *st, cstring_t reason,
				 const struct comm_addr *prod_hint)
{
    /* Reentrancy hazard: can call enter_new_state/enter_state_* */
    if (st->state!=SITE_RUN) return False;
    slog(st,LOG_SETUP_INIT,"initiating key exchange (%s)",reason);
    if (st->addresses) {
	slog(st,LOG_SETUP_INIT,"resolving peer address(es)");
	return enter_state_resolve(st);
    } else if (transport_compute_setupinit_peers(st,0,0,prod_hint)) {
	return enter_new_state(st,SITE_SENTMSG1,0);
    }
    slog(st,LOG_SETUP_INIT,"key exchange failed: no address for peer");
    return False;
}

static void activate_new_key(struct site *st)
{
    struct transform_inst_if *t;

    /* We have three transform instances, which we swap between old,
       active and setup */
    t=st->auxiliary_key.transform;
    st->auxiliary_key.transform=st->current.transform;
    st->current.transform=st->new_transform;
    st->new_transform=t;
    dispose_transform(&st->new_transform);

    st->timeout=0;
    st->auxiliary_is_new=0;
    st->auxiliary_key.key_timeout=st->current.key_timeout;
    st->current.key_timeout=st->now+st->key_lifetime;
    st->renegotiate_key_time=st->now+st->key_renegotiate_time;
    transport_peers_copy(st,&st->peers,&st->setup_peers);
    st->current.remote_session_id=st->setup_session_id;

    /* Compute the inter-site MTU.  This is min( our_mtu, their_mtu ).
     * But their mtu be unspecified, in which case we just use ours. */
    uint32_t intersite_mtu=
	MIN(st->mtu_target, st->remote_adv_mtu ?: ~(uint32_t)0);
    st->netlink->set_mtu(st->netlink->st,intersite_mtu);

    slog(st,LOG_ACTIVATE_KEY,"new key activated"
	 " (mtu ours=%"PRId32" theirs=%"PRId32" intersite=%"PRId32")",
	 st->mtu_target, st->remote_adv_mtu, intersite_mtu);
    enter_state_run(st);
}

static void delete_one_key(struct site *st, struct data_key *key,
			   cstring_t reason, cstring_t which, uint32_t loglevel)
{
    if (!is_transform_valid(key->transform)) return;
    if (reason) slog(st,loglevel,"%s deleted (%s)",which,reason);
    dispose_transform(&key->transform);
    key->key_timeout=0;
}

static void delete_keys(struct site *st, cstring_t reason, uint32_t loglevel)
{
    if (current_valid(st)) {
	slog(st,loglevel,"session closed (%s)",reason);

	delete_one_key(st,&st->current,0,0,0);
	set_link_quality(st);
    }
    delete_one_key(st,&st->auxiliary_key,0,0,0);
}

static void state_assert(struct site *st, bool_t ok)
{
    if (!ok) fatal("site:state_assert");
}

static void enter_state_stop(struct site *st)
{
    st->state=SITE_STOP;
    st->timeout=0;
    delete_keys(st,"entering state STOP",LOG_TIMEOUT_KEY);
    dispose_transform(&st->new_transform);
}

static void set_link_quality(struct site *st)
{
    uint32_t quality;
    if (current_valid(st))
	quality=LINK_QUALITY_UP;
    else if (st->state==SITE_WAIT || st->state==SITE_STOP)
	quality=LINK_QUALITY_DOWN;
    else if (st->addresses)
	quality=LINK_QUALITY_DOWN_CURRENT_ADDRESS;
    else if (transport_peers_valid(&st->peers))
	quality=LINK_QUALITY_DOWN_STALE_ADDRESS;
    else
	quality=LINK_QUALITY_DOWN;

    st->netlink->set_quality(st->netlink->st,quality);
}

static void enter_state_run(struct site *st)
{
    slog(st,LOG_STATE,"entering state RUN%s",
	 current_valid(st) ? " (keyed)" : " (unkeyed)");
    st->state=SITE_RUN;
    st->timeout=0;

    st->setup_session_id=0;
    transport_peers_clear(st,&st->setup_peers);
    FILLZERO(st->localN);
    FILLZERO(st->remoteN);
    dispose_transform(&st->new_transform);
    memset(st->dhsecret,0,st->dh->len);
    if (st->sharedsecret) memset(st->sharedsecret,0,st->sharedsecretlen);
    set_link_quality(st);

    if (st->keepalive && !current_valid(st))
	initiate_key_setup(st, "keepalive", 0);
}

static bool_t ensure_resolving(struct site *st)
{
    /* Reentrancy hazard: may call site_resolve_callback and hence
     * enter_new_state, enter_state_* and generate_msg*. */
    if (st->resolving_count)
        return True;

    assert(st->addresses);

    /* resolver->request might reentrantly call site_resolve_callback
     * which will decrement st->resolving, so we need to increment it
     * twice beforehand to prevent decrement from thinking we're
     * finished, and decrement it ourselves.  Alternatively if
     * everything fails then there are no callbacks due and we simply
     * set it to 0 and return false.. */
    st->resolving_n_results_stored=0;
    st->resolving_n_results_all=0;
    st->resolving_count+=2;
    const char **addrp=st->addresses;
    const char *address;
    bool_t anyok=False;
    for (; (address=*addrp++); ) {
	bool_t ok = st->resolver->request(st->resolver->st,address,
					  st->remoteport,st->comms[0],
					  site_resolve_callback,st);
	if (ok)
	    st->resolving_count++;
	anyok|=ok;
    }
    if (!anyok) {
	st->resolving_count=0;
	return False;
    }
    decrement_resolving_count(st,2);
    return True;
}

static bool_t enter_state_resolve(struct site *st)
{
    /* Reentrancy hazard!  See ensure_resolving. */
    state_assert(st,st->state==SITE_RUN);
    slog(st,LOG_STATE,"entering state RESOLVE");
    st->state=SITE_RESOLVE;
    return ensure_resolving(st);
}

static bool_t enter_new_state(struct site *st, uint32_t next,
			      const struct msg *prompt
			      /* may be 0 for SENTMSG1 */)
{
    bool_t (*gen)(struct site *st, const struct msg *prompt);
    int r;

    slog(st,LOG_STATE,"entering state %s",state_name(next));
    switch(next) {
    case SITE_SENTMSG1:
	state_assert(st,st->state==SITE_RUN || st->state==SITE_RESOLVE);
	if (!kex_init(st)) return False;
	gen=generate_msg1;
	st->msg1_crossed_logged = False;
	break;
    case SITE_SENTMSG2:
	state_assert(st,st->state==SITE_RUN || st->state==SITE_RESOLVE ||
		     st->state==SITE_SENTMSG1 || st->state==SITE_WAIT);
	if (!kex_init(st)) return False;
	gen=generate_msg2;
	break;
    case SITE_SENTMSG3:
	state_assert(st,st->state==SITE_SENTMSG1);
	BUF_FREE(&st->buffer);
	gen=generate_msg3;
	break;
    case SITE_SENTMSG4:
	state_assert(st,st->state==SITE_SENTMSG2);
	BUF_FREE(&st->buffer);
	gen=generate_msg4;
	break;
    case SITE_SENTMSG5:
	state_assert(st,st->state==SITE_SENTMSG3);
	BUF_FREE(&st->buffer);
	gen=generate_msg5;
	break;
    case SITE_RUN:
	state_assert(st,st->state==SITE_SENTMSG4);
	BUF_FREE(&st->buffer);
	gen=generate_msg6;
	break;
    default:
	gen=NULL;
	fatal("enter_new_state(%s): invalid new state",state_name(next));
	break;
    }

    if (hacky_par_start_failnow()) return False;

    r= gen(st,prompt) && send_msg(st);

    hacky_par_end(&r,
		  st->setup_retries, st->setup_retry_interval,
		  send_msg, st);
    
    if (r) {
	st->state=next;
	if (next==SITE_RUN) {
	    BUF_FREE(&st->buffer); /* Never reused */
	    st->timeout=0; /* Never retransmit */
	    activate_new_key(st);
	}
	return True;
    }
    slog(st,LOG_ERROR,"error entering state %s",state_name(next));
    st->buffer.free=False; /* Unconditionally use the buffer; it may be
			      in either state, and enter_state_wait() will
			      do a BUF_FREE() */
    enter_state_wait(st);
    return False;
}

/* msg7 tells our peer that we're about to forget our key */
static bool_t send_msg7(struct site *st, cstring_t reason)
{
    cstring_t transform_err;

    if (current_valid(st) && st->buffer.free
	&& transport_peers_valid(&st->peers)) {
	BUF_ALLOC(&st->buffer,"site:MSG7");
	buffer_init(&st->buffer,calculate_max_start_pad());
	buf_append_uint32(&st->buffer,LABEL_MSG7);
	buf_append_string(&st->buffer,reason);
	if (call_transform_forwards(st, st->current.transform,
				    &st->buffer, &transform_err))
	    goto free_out;
	buf_prepend_uint32(&st->buffer,LABEL_MSG0);
	buf_prepend_uint32(&st->buffer,st->index);
	buf_prepend_uint32(&st->buffer,st->current.remote_session_id);
	transport_xmit(st,&st->peers,&st->buffer,True);
	BUF_FREE(&st->buffer);
    free_out:
	return True;
    }
    return False;
}

/* We go into this state if our peer becomes uncommunicative. Similar to
   the "stop" state, we forget all session keys for a while, before
   re-entering the "run" state. */
static void enter_state_wait(struct site *st)
{
    slog(st,LOG_STATE,"entering state WAIT");
    st->timeout=st->now+wait_timeout(st);
    st->state=SITE_WAIT;
    set_link_quality(st);
    BUF_FREE(&st->buffer); /* will have had an outgoing packet in it */
    /* XXX Erase keys etc. */
}

static void generate_prod(struct site *st, struct buffer_if *buf)
{
    buffer_init(buf,0);
    buf_append_uint32(buf,0);
    buf_append_uint32(buf,0);
    buf_append_uint32(buf,LABEL_PROD);
    buf_append_string(buf,st->localname);
    buf_append_string(buf,st->remotename);
}

static void generate_send_prod(struct site *st,
			       const struct comm_addr *source)
{
    if (!st->allow_send_prod) return; /* too soon */
    if (!(st->state==SITE_RUN || st->state==SITE_RESOLVE ||
	  st->state==SITE_WAIT)) return; /* we'd ignore peer's MSG1 */

    slog(st,LOG_SETUP_INIT,"prodding peer for key exchange");
    st->allow_send_prod=0;
    generate_prod(st,&st->scratch);
    bool_t ok = comm_addr_sendmsg(st, source, &st->scratch);
    dump_packet(st,&st->scratch,source,False,ok);
}

static inline void site_settimeout(uint64_t timeout, int *timeout_io)
{
    if (timeout) {
	int64_t offset=timeout-*now;
	if (offset<0) offset=0;
	if (offset>INT_MAX) offset=INT_MAX;
	if (*timeout_io<0 || offset<*timeout_io)
	    *timeout_io=offset;
    }
}

static int site_beforepoll(void *sst, struct pollfd *fds, int *nfds_io,
			   int *timeout_io)
{
    struct site *st=sst;

    BEFOREPOLL_WANT_FDS(0); /* We don't use any file descriptors */
    st->now=*now;

    /* Work out when our next timeout is. The earlier of 'timeout' or
       'current.key_timeout'. A stored value of '0' indicates no timeout
       active. */
    site_settimeout(st->timeout, timeout_io);
    site_settimeout(st->current.key_timeout, timeout_io);
    site_settimeout(st->auxiliary_key.key_timeout, timeout_io);

    return 0; /* success */
}

static void check_expiry(struct site *st, struct data_key *key,
			 const char *which)
{
    if (key->key_timeout && *now>key->key_timeout) {
	delete_one_key(st,key,"maximum life exceeded",which,LOG_TIMEOUT_KEY);
    }
}

/* NB site_afterpoll will be called before site_beforepoll is ever called */
static void site_afterpoll(void *sst, struct pollfd *fds, int nfds)
{
    struct site *st=sst;

    st->now=*now;
    if (st->timeout && *now>st->timeout) {
	st->timeout=0;
	if (st->state>=SITE_SENTMSG1 && st->state<=SITE_SENTMSG5) {
	    if (!hacky_par_start_failnow())
	        send_msg(st);
	} else if (st->state==SITE_WAIT) {
	    enter_state_run(st);
	} else {
	    slog(st,LOG_ERROR,"site_afterpoll: unexpected timeout, state=%d",
		 st->state);
	}
    }
    check_expiry(st,&st->current,"current key");
    check_expiry(st,&st->auxiliary_key,"auxiliary key");
}

/* This function is called by the netlink device to deliver packets
   intended for the remote network. The packet is in "raw" wire
   format, but is guaranteed to be word-aligned. */
static void site_outgoing(void *sst, struct buffer_if *buf)
{
    struct site *st=sst;
    cstring_t transform_err;
    
    if (st->state==SITE_STOP) {
	BUF_FREE(buf);
	return;
    }

    st->allow_send_prod=1;

    /* In all other states we consider delivering the packet if we have
       a valid key and a valid address to send it to. */
    if (current_valid(st) && transport_peers_valid(&st->peers)) {
	/* Transform it and send it */
	if (buf->size>0) {
	    buf_prepend_uint32(buf,LABEL_MSG9);
	    if (call_transform_forwards(st, st->current.transform,
					buf, &transform_err))
		goto free_out;
	    buf_prepend_uint32(buf,LABEL_MSG0);
	    buf_prepend_uint32(buf,st->index);
	    buf_prepend_uint32(buf,st->current.remote_session_id);
	    transport_xmit(st,&st->peers,buf,False);
	}
    free_out:
	BUF_FREE(buf);
	return;
    }

    slog(st,LOG_DROP,"discarding outgoing packet of size %d",buf->size);
    BUF_FREE(buf);
    initiate_key_setup(st,"outgoing packet",0);
}

static bool_t named_for_us(struct site *st, const struct buffer_if *buf_in,
			   uint32_t type, struct msg *m)
    /* For packets which are identified by the local and remote names.
     * If it has our name and our peer's name in it it's for us. */
{
    struct buffer_if buf[1];
    buffer_readonly_clone(buf,buf_in);
    return unpick_msg(st,type,buf,m)
	&& name_matches(&m->remote,st->remotename)
	&& name_matches(&m->local,st->localname);
}

static bool_t we_have_priority(struct site *st, const struct msg *m) {
    if (st->local_capabilities & m->remote_capabilities &
	CAPAB_PRIORITY_MOBILE) {
	if (st->local_mobile) return True;
	if (st-> peer_mobile) return False;
    }
    return st->our_name_later;
}

static bool_t setup_late_msg_ok(struct site *st, 
				const struct buffer_if *buf_in,
				uint32_t msgtype,
				const struct comm_addr *source,
				struct msg *m /* returned */) {
    /* For setup packets which seem from their type like they are
     * late.  Maybe they came via a different path.  All we do is make
     * a note of the sending address, iff they look like they are part
     * of the current key setup attempt. */
    if (!named_for_us(st,buf_in,msgtype,m))
	/* named_for_us calls unpick_msg which gets the nonces */
	return False;
    if (!consttime_memeq(m->nR,st->remoteN,NONCELEN) ||
	!consttime_memeq(m->nL,st->localN, NONCELEN))
	/* spoof ?  from stale run ?  who knows */
	return False;
    transport_setup_msgok(st,source);
    return True;
}

/* This function is called by the communication device to deliver
   packets from our peers.
   It should return True if the packet is recognised as being for
   this current site instance (and should therefore not be processed
   by other sites), even if the packet was otherwise ignored. */
static bool_t site_incoming(void *sst, struct buffer_if *buf,
			    const struct comm_addr *source,
			    struct priomsg *whynot)
{
    struct site *st=sst;

    if (buf->size < 12) return False;

    uint32_t dest=get_uint32(buf->start);
    uint32_t msgtype=get_uint32(buf->start+8);
    struct msg msg;
      /* initialised by named_for_us, or process_msgN for N!=1 */

    if (msgtype==LABEL_MSG1) {
	if (!named_for_us(st,buf,msgtype,&msg))
	    return False;
	/* It's a MSG1 addressed to us. Decide what to do about it. */
	dump_packet(st,buf,source,True,True);
	if (st->state==SITE_RUN || st->state==SITE_RESOLVE ||
	    st->state==SITE_WAIT) {
	    /* We should definitely process it */
	    transport_compute_setupinit_peers(st,0,0,source);
	    if (process_msg1(st,buf,source,&msg)) {
		slog(st,LOG_SETUP_INIT,"key setup initiated by peer");
		bool_t entered=enter_new_state(st,SITE_SENTMSG2,&msg);
		if (entered && st->addresses && st->local_mobile)
		    /* We must do this as the very last thing, because
		       the resolver callback might reenter us. */
		    ensure_resolving(st);
	    } else {
		slog(st,LOG_ERROR,"failed to process incoming msg1");
	    }
	    BUF_FREE(buf);
	    return True;
	} else if (st->state==SITE_SENTMSG1) {
	    /* We've just sent a message 1! They may have crossed on
	       the wire. If we have priority then we ignore the
	       incoming one, otherwise we process it as usual. */
	    if (we_have_priority(st,&msg)) {
		BUF_FREE(buf);
		if (!st->msg1_crossed_logged++)
		    slog(st,LOG_SETUP_INIT,"crossed msg1s; we are higher "
			 "priority => ignore incoming msg1");
		return True;
	    } else {
		slog(st,LOG_SETUP_INIT,"crossed msg1s; we are lower "
		     "priority => use incoming msg1");
		if (process_msg1(st,buf,source,&msg)) {
		    BUF_FREE(&st->buffer); /* Free our old message 1 */
		    transport_setup_msgok(st,source);
		    enter_new_state(st,SITE_SENTMSG2,&msg);
		} else {
		    slog(st,LOG_ERROR,"failed to process an incoming "
			 "crossed msg1 (we have low priority)");
		}
		BUF_FREE(buf);
		return True;
	    }
	} else if (st->state==SITE_SENTMSG2 ||
		   st->state==SITE_SENTMSG4) {
	    if (consttime_memeq(msg.nR,st->remoteN,NONCELEN)) {
		/* We are ahead in the protocol, but that msg1 had the
		 * peer's nonce so presumably it is from this key
		 * exchange run, via a slower route */
		transport_setup_msgok(st,source);
	    } else {
		slog(st,LOG_UNEXPECTED,"competing incoming message 1");
	    }
	    BUF_FREE(buf);
	    return True;
	}
	/* The message 1 was received at an unexpected stage of the
	   key setup.  Well, they lost the race. */
	slog(st,LOG_UNEXPECTED,"unexpected incoming message 1");
	BUF_FREE(buf);
	return True;
    }
    if (msgtype==LABEL_PROD) {
	if (!named_for_us(st,buf,msgtype,&msg))
	    return False;
	dump_packet(st,buf,source,True,True);
	if (st->state!=SITE_RUN) {
	    slog(st,LOG_DROP,"ignoring PROD when not in state RUN");
	} else if (current_valid(st)) {
	    slog(st,LOG_DROP,"ignoring PROD when we think we have a key");
	} else {
	    initiate_key_setup(st,"peer sent PROD packet",source);
	}
	BUF_FREE(buf);
	return True;
    }
    if (dest==st->index) {
	/* Explicitly addressed to us */
	if (msgtype!=LABEL_MSG0) dump_packet(st,buf,source,True,True);
	switch (msgtype) {
	case LABEL_NAK:
	    /* If the source is our current peer then initiate a key setup,
	       because our peer's forgotten the key */
	    if (get_uint32(buf->start+4)==st->current.remote_session_id) {
		bool_t initiated;
		initiated = initiate_key_setup(st,"received a NAK",source);
		if (!initiated) generate_send_prod(st,source);
	    } else {
		slog(st,LOG_SEC,"bad incoming NAK");
	    }
	    break;
	case LABEL_MSG0:
	    process_msg0(st,buf,source);
	    break;
	case LABEL_MSG1:
	    /* Setup packet: should not have been explicitly addressed
	       to us */
	    slog(st,LOG_SEC,"incoming explicitly addressed msg1");
	    break;
	case LABEL_MSG2:
	    /* Setup packet: expected only in state SENTMSG1 */
	    if (st->state!=SITE_SENTMSG1) {
		if ((st->state==SITE_SENTMSG3 ||
		     st->state==SITE_SENTMSG5) &&
		    setup_late_msg_ok(st,buf,msgtype,source,&msg))
		    break;
		slog(st,LOG_UNEXPECTED,"unexpected MSG2");
	    } else if (process_msg2(st,buf,source,&msg)) {
		transport_setup_msgok(st,source);
		enter_new_state(st,SITE_SENTMSG3,&msg);
	    } else {
		slog(st,LOG_SEC,"invalid MSG2");
	    }
	    break;
	case CASES_MSG3_KNOWN:
	    /* Setup packet: expected only in state SENTMSG2 */
	    if (st->state!=SITE_SENTMSG2) {
		if ((st->state==SITE_SENTMSG4) &&
		    setup_late_msg_ok(st,buf,msgtype,source,&msg))
		    break;
		slog(st,LOG_UNEXPECTED,"unexpected MSG3");
	    } else if (process_msg3(st,buf,source,msgtype,&msg)) {
		transport_setup_msgok(st,source);
		enter_new_state(st,SITE_SENTMSG4,&msg);
	    } else {
		slog(st,LOG_SEC,"invalid MSG3");
	    }
	    break;
	case LABEL_MSG4:
	    /* Setup packet: expected only in state SENTMSG3 */
	    if (st->state!=SITE_SENTMSG3) {
		if ((st->state==SITE_SENTMSG5) &&
		    setup_late_msg_ok(st,buf,msgtype,source,&msg))
		    break;
		slog(st,LOG_UNEXPECTED,"unexpected MSG4");
	    } else if (process_msg4(st,buf,source,&msg)) {
		transport_setup_msgok(st,source);
		enter_new_state(st,SITE_SENTMSG5,&msg);
	    } else {
		slog(st,LOG_SEC,"invalid MSG4");
	    }
	    break;
	case LABEL_MSG5:
	    /* Setup packet: expected only in state SENTMSG4 */
	    /* (may turn up in state RUN if our return MSG6 was lost
	       and the new key has already been activated. In that
	       case we discard it. The peer will realise that we
	       are using the new key when they see our data packets.
	       Until then the peer's data packets to us get discarded. */
	    if (st->state==SITE_SENTMSG4) {
		if (process_msg5(st,buf,source,st->new_transform)) {
		    transport_setup_msgok(st,source);
		    enter_new_state(st,SITE_RUN,&msg);
		} else {
		    slog(st,LOG_SEC,"invalid MSG5");
		}
	    } else if (st->state==SITE_RUN) {
		if (process_msg5(st,buf,source,st->current.transform)) {
		    slog(st,LOG_DROP,"got MSG5, retransmitting MSG6");
		    transport_setup_msgok(st,source);
		    create_msg6(st,st->current.transform,
				st->current.remote_session_id);
		    transport_xmit(st,&st->peers,&st->buffer,True);
		    BUF_FREE(&st->buffer);
		} else {
		    slog(st,LOG_SEC,"invalid MSG5 (in state RUN)");
		}
	    } else {
		slog(st,LOG_UNEXPECTED,"unexpected MSG5");
	    }
	    break;
	case LABEL_MSG6:
	    /* Setup packet: expected only in state SENTMSG5 */
	    if (st->state!=SITE_SENTMSG5) {
		slog(st,LOG_UNEXPECTED,"unexpected MSG6");
	    } else if (process_msg6(st,buf,source)) {
		BUF_FREE(&st->buffer); /* Free message 5 */
		transport_setup_msgok(st,source);
		activate_new_key(st);
	    } else {
		slog(st,LOG_SEC,"invalid MSG6");
	    }
	    break;
	default:
	    slog(st,LOG_SEC,"received message of unknown type 0x%08x",
		 msgtype);
	    break;
	}
	BUF_FREE(buf);
	return True;
    }

    return False;
}

static void site_control(void *vst, bool_t run)
{
    struct site *st=vst;
    if (run) enter_state_run(st);
    else enter_state_stop(st);
}

static void site_phase_hook(void *sst, uint32_t newphase)
{
    struct site *st=sst;

    /* The program is shutting down; tell our peer */
    send_msg7(st,"shutting down");
}

static void site_childpersist_clearkeys(void *sst, uint32_t newphase)
{
    struct site *st=sst;
    dispose_transform(&st->current.transform);
    dispose_transform(&st->auxiliary_key.transform);
    dispose_transform(&st->new_transform);
    /* Not much point overwiting the signing key, since we loaded it
       from disk, and it is only valid prospectively if at all,
       anyway. */
    /* XXX it would be best to overwrite the DH state, because that
       _is_ relevant to forward secrecy.  However we have no
       convenient interface for doing that and in practice gmp has
       probably dribbled droppings all over the malloc arena.  A good
       way to fix this would be to have a privsep child for asymmetric
       crypto operations, but that's a task for another day. */
}

static list_t *site_apply(closure_t *self, struct cloc loc, dict_t *context,
			  list_t *args)
{
    static uint32_t index_sequence;
    struct site *st;
    item_t *item;
    dict_t *dict;
    int i;

    NEW(st);

    st->cl.description="site";
    st->cl.type=CL_SITE;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.control=site_control;
    st->ops.status=site_status;

    /* First parameter must be a dict */
    item=list_elem(args,0);
    if (!item || item->type!=t_dict)
	cfgfatal(loc,"site","parameter must be a dictionary\n");
    
    dict=item->data.dict;
    st->localname=dict_read_string(dict, "local-name", True, "site", loc);
    st->remotename=dict_read_string(dict, "name", True, "site", loc);

    st->keepalive=dict_read_bool(dict,"keepalive",False,"site",loc,False);

    st->peer_mobile=dict_read_bool(dict,"mobile",False,"site",loc,False);
    st->local_mobile=
	dict_read_bool(dict,"local-mobile",False,"site",loc,False);

    /* Sanity check (which also allows the 'sites' file to include
       site() closures for all sites including our own): refuse to
       talk to ourselves */
    if (strcmp(st->localname,st->remotename)==0) {
	Message(M_DEBUG,"site %s: local-name==name -> ignoring this site\n",
		st->localname);
	if (st->peer_mobile != st->local_mobile)
	    cfgfatal(loc,"site","site %s's peer-mobile=%d"
		    " but our local-mobile=%d\n",
		    st->localname, st->peer_mobile, st->local_mobile);
	free(st);
	return NULL;
    }
    if (st->peer_mobile && st->local_mobile) {
	Message(M_WARNING,"site %s: site is mobile but so are we"
		" -> ignoring this site\n", st->remotename);
	free(st);
	return NULL;
    }

    assert(index_sequence < 0xffffffffUL);
    st->index = ++index_sequence;
    st->local_capabilities = 0;
    st->early_capabilities = CAPAB_PRIORITY_MOBILE;
    st->netlink=find_cl_if(dict,"link",CL_NETLINK,True,"site",loc);

#define GET_CLOSURE_LIST(dictkey,things,nthings,CL_TYPE) do{		\
    list_t *things##_cfg=dict_lookup(dict,dictkey);			\
    if (!things##_cfg)							\
	cfgfatal(loc,"site","closure list \"%s\" not found\n",dictkey);	\
    st->nthings=list_length(things##_cfg);				\
    NEW_ARY(st->things,st->nthings);					\
    assert(st->nthings);						\
    for (i=0; i<st->nthings; i++) {					\
	item_t *item=list_elem(things##_cfg,i);				\
	if (item->type!=t_closure)					\
	    cfgfatal(loc,"site","%s is not a closure\n",dictkey);	\
	closure_t *cl=item->data.closure;				\
	if (cl->type!=CL_TYPE)						\
	    cfgfatal(loc,"site","%s closure wrong type\n",dictkey);	\
	st->things[i]=cl->interface;					\
    }									\
}while(0)

    GET_CLOSURE_LIST("comm",comms,ncomms,CL_COMM);

    NEW_ARY(st->commclientinfos, st->ncomms);
    dict_t *comminfo = dict_read_dict(dict,"comm-info",False,"site",loc);
    for (i=0; i<st->ncomms; i++) {
	st->commclientinfos[i] =
	    !comminfo ? 0 :
	    st->comms[i]->clientinfo(st->comms[i],comminfo,loc);
    }

    st->resolver=find_cl_if(dict,"resolver",CL_RESOLVER,True,"site",loc);
    st->log=find_cl_if(dict,"log",CL_LOG,True,"site",loc);
    st->random=find_cl_if(dict,"random",CL_RANDOMSRC,True,"site",loc);

    st->privkey=find_cl_if(dict,"local-key",CL_SIGPRIVKEY,True,"site",loc);
    st->addresses=dict_read_string_array(dict,"address",False,"site",loc,0);
    if (st->addresses)
	st->remoteport=dict_read_number(dict,"port",True,"site",loc,0);
    else st->remoteport=0;
    st->pubkey=find_cl_if(dict,"key",CL_SIGPUBKEY,True,"site",loc);

    GET_CLOSURE_LIST("transform",transforms,ntransforms,CL_TRANSFORM);

    st->dh=find_cl_if(dict,"dh",CL_DH,True,"site",loc);

    if (st->privkey->sethash || st->pubkey->sethash) {
	struct hash_if *hash=find_cl_if(dict,"hash",CL_HASH,True,"site",loc);
	if (st->privkey->sethash) st->privkey->sethash(st->privkey->st,hash);
	if (st->pubkey->sethash) st->pubkey->sethash(st->pubkey->st,hash);
    }

#define DEFAULT(D) (st->peer_mobile || st->local_mobile	\
                    ? DEFAULT_MOBILE_##D : DEFAULT_##D)
#define CFG_NUMBER(k,D) dict_read_number(dict,(k),False,"site",loc,DEFAULT(D));

    st->key_lifetime=         CFG_NUMBER("key-lifetime",  KEY_LIFETIME);
    st->setup_retries=        CFG_NUMBER("setup-retries", SETUP_RETRIES);
    st->setup_retry_interval= CFG_NUMBER("setup-timeout", SETUP_RETRY_INTERVAL);
    st->wait_timeout_mean=    CFG_NUMBER("wait-time",     WAIT_TIME);
    st->mtu_target= dict_read_number(dict,"mtu-target",False,"site",loc,0);

    st->mobile_peer_expiry= dict_read_number(
       dict,"mobile-peer-expiry",False,"site",loc,DEFAULT_MOBILE_PEER_EXPIRY);

    const char *peerskey= st->peer_mobile
	? "mobile-peers-max" : "static-peers-max";
    st->transport_peers_max= dict_read_number(
	dict,peerskey,False,"site",loc, st->addresses ? 4 : 3);
    if (st->transport_peers_max<1 ||
	st->transport_peers_max>MAX_PEER_ADDRS) {
	cfgfatal(loc,"site", "%s must be in range 1.."
		 STRING(MAX_PEER_ADDRS) "\n", peerskey);
    }

    if (st->key_lifetime < DEFAULT(KEY_RENEGOTIATE_GAP)*2)
	st->key_renegotiate_time=st->key_lifetime/2;
    else
	st->key_renegotiate_time=st->key_lifetime-DEFAULT(KEY_RENEGOTIATE_GAP);
    st->key_renegotiate_time=dict_read_number(
	dict,"renegotiate-time",False,"site",loc,st->key_renegotiate_time);
    if (st->key_renegotiate_time > st->key_lifetime) {
	cfgfatal(loc,"site",
		 "renegotiate-time must be less than key-lifetime\n");
    }

    st->log_events=string_list_to_word(dict_lookup(dict,"log-events"),
				       log_event_table,"site");

    st->resolving_count=0;
    st->allow_send_prod=0;

    st->tunname=safe_malloc(strlen(st->localname)+strlen(st->remotename)+5,
			    "site_apply");
    sprintf(st->tunname,"%s<->%s",st->localname,st->remotename);

    /* The information we expect to see in incoming messages of type 1 */
    /* fixme: lots of unchecked overflows here, but the results are only
       corrupted packets rather than undefined behaviour */
    st->our_name_later=(strcmp(st->localname,st->remotename)>0);

    buffer_new(&st->buffer,SETUP_BUFFER_LEN);

    buffer_new(&st->scratch,SETUP_BUFFER_LEN);
    BUF_ALLOC(&st->scratch,"site:scratch");

    /* We are interested in poll(), but only for timeouts. We don't have
       any fds of our own. */
    register_for_poll(st, site_beforepoll, site_afterpoll, "site");
    st->timeout=0;

    st->remote_capabilities=0;
    st->chosen_transform=0;
    st->current.key_timeout=0;
    st->auxiliary_key.key_timeout=0;
    transport_peers_clear(st,&st->peers);
    transport_peers_clear(st,&st->setup_peers);
    /* XXX mlock these */
    st->dhsecret=safe_malloc(st->dh->len,"site:dhsecret");
    st->sharedsecretlen=st->sharedsecretallocd=0;
    st->sharedsecret=0;

#define SET_CAPBIT(bit) do {						\
    uint32_t capflag = 1UL << (bit);					\
    if (st->local_capabilities & capflag)				\
	slog(st,LOG_ERROR,"capability bit"				\
	     " %d (%#"PRIx32") reused", (bit), capflag);		\
    st->local_capabilities |= capflag;					\
} while (0)

    for (i=0; i<st->ntransforms; i++)
	SET_CAPBIT(st->transforms[i]->capab_bit);

#undef SET_CAPBIT

    if (st->local_mobile || st->peer_mobile)
	st->local_capabilities |= CAPAB_PRIORITY_MOBILE;

    /* We need to register the remote networks with the netlink device */
    uint32_t netlink_mtu; /* local virtual interface mtu */
    st->netlink->reg(st->netlink->st, site_outgoing, st, &netlink_mtu);
    if (!st->mtu_target)
	st->mtu_target=netlink_mtu;
    
    for (i=0; i<st->ncomms; i++)
	st->comms[i]->request_notify(st->comms[i]->st, st, site_incoming);

    st->current.transform=0;
    st->auxiliary_key.transform=0;
    st->new_transform=0;
    st->auxiliary_is_new=0;

    enter_state_stop(st);

    add_hook(PHASE_SHUTDOWN,site_phase_hook,st);
    add_hook(PHASE_CHILDPERSIST,site_childpersist_clearkeys,st);

    return new_closure(&st->cl);
}

void site_module(dict_t *dict)
{
    add_closure(dict,"site",site_apply);
}


/***** TRANSPORT PEERS definitions *****/

static void transport_peers_debug(struct site *st, transport_peers *dst,
				  const char *didwhat,
				  int nargs, const struct comm_addr *args,
				  size_t stride) {
    int i;
    char *argp;

    if (!(st->log_events & LOG_PEER_ADDRS))
	return; /* an optimisation */

    slog(st, LOG_PEER_ADDRS, "peers (%s) %s nargs=%d => npeers=%d",
	 (dst==&st->peers ? "data" :
	  dst==&st->setup_peers ? "setup" : "UNKNOWN"),
	 didwhat, nargs, dst->npeers);

    for (i=0, argp=(void*)args;
	 i<nargs;
	 i++, (argp+=stride?stride:sizeof(*args))) {
	const struct comm_addr *ca=(void*)argp;
	slog(st, LOG_PEER_ADDRS, " args: addrs[%d]=%s",
	     i, comm_addr_to_string(ca));
    }
    for (i=0; i<dst->npeers; i++) {
	struct timeval diff;
	timersub(tv_now,&dst->peers[i].last,&diff);
	const struct comm_addr *ca=&dst->peers[i].addr;
	slog(st, LOG_PEER_ADDRS, " peers: addrs[%d]=%s T-%ld.%06ld",
	     i, comm_addr_to_string(ca),
	     (unsigned long)diff.tv_sec, (unsigned long)diff.tv_usec);
    }
}

static void transport_peers_expire(struct site *st, transport_peers *peers) {
    /* peers must be sorted first */
    int previous_peers=peers->npeers;
    struct timeval oldest;
    oldest.tv_sec  = tv_now->tv_sec - st->mobile_peer_expiry;
    oldest.tv_usec = tv_now->tv_usec;
    while (peers->npeers>1 &&
	   timercmp(&peers->peers[peers->npeers-1].last, &oldest, <))
	peers->npeers--;
    if (peers->npeers != previous_peers)
	transport_peers_debug(st,peers,"expire", 0,0,0);
}

static bool_t transport_peer_record_one(struct site *st, transport_peers *peers,
					const struct comm_addr *ca,
					const struct timeval *tv) {
    /* returns false if output is full */
    int search;

    if (peers->npeers >= st->transport_peers_max)
	return 0;

    for (search=0; search<peers->npeers; search++)
	if (comm_addr_equal(&peers->peers[search].addr, ca))
	    return 1;

    peers->peers[peers->npeers].addr = *ca;
    peers->peers[peers->npeers].last = *tv;
    peers->npeers++;
    return 1;
}

static void transport_record_peers(struct site *st, transport_peers *peers,
				   const struct comm_addr *addrs, int naddrs,
				   const char *m) {
    /* We add addrs into peers.  The new entries end up at the front
     * and displace entries towards the end (perhaps even off the
     * end).  Any existing matching entries are moved up to the front.
     *
     * Caller must first call transport_peers_expire. */

    if (naddrs==1) {
	/* avoids debug for uninteresting updates */
	int i;
	for (i=0; i<peers->npeers; i++) {
	    if (comm_addr_equal(&addrs[0], &peers->peers[i].addr)) {
		memmove(peers->peers+1, peers->peers,
			sizeof(peers->peers[0]) * i);
		peers->peers[0].addr = addrs[0];
		peers->peers[0].last = *tv_now;
		return;
	    }
	}
    }

    int old_npeers=peers->npeers;
    transport_peer old_peers[old_npeers];
    COPY_ARRAY(old_peers,peers->peers,old_npeers);

    peers->npeers=0;
    int i;
    for (i=0; i<naddrs; i++) {
	if (!transport_peer_record_one(st,peers, &addrs[i], tv_now))
	    break;
    }
    for (i=0; i<old_npeers; i++) {
	const transport_peer *old=&old_peers[i];
	if (!transport_peer_record_one(st,peers, &old->addr, &old->last))
	    break;
    }

    transport_peers_debug(st,peers,m, naddrs,addrs,0);
}

static void transport_expire_record_peers(struct site *st,
					  transport_peers *peers,
					  const struct comm_addr *addrs,
					  int naddrs, const char *m) {
    /* Convenience function */
    transport_peers_expire(st,peers);
    transport_record_peers(st,peers,addrs,naddrs,m);
}

static bool_t transport_compute_setupinit_peers(struct site *st,
        const struct comm_addr *configured_addrs /* 0 if none or not found */,
        int n_configured_addrs /* 0 if none or not found */,
        const struct comm_addr *incoming_packet_addr /* 0 if none */) {
    if (!n_configured_addrs && !incoming_packet_addr &&
	!transport_peers_valid(&st->peers))
	return False;

    slog(st,LOG_SETUP_INIT,
	 "using: %d configured addr(s);%s %d old peer addrs(es)",
	 n_configured_addrs,
	 incoming_packet_addr ? " incoming packet address;" : "",
	 st->peers.npeers);

    /* Non-mobile peers try addresses until one is plausible.  The
     * effect is that this code always tries first the configured
     * address if supplied, or otherwise the address of the incoming
     * PROD, or finally the existing data peer if one exists; this is
     * as desired. */

    transport_peers_copy(st,&st->setup_peers,&st->peers);
    transport_peers_expire(st,&st->setup_peers);

    if (incoming_packet_addr)
	transport_record_peers(st,&st->setup_peers,
			       incoming_packet_addr,1, "incoming");

    if (n_configured_addrs)
	transport_record_peers(st,&st->setup_peers,
			      configured_addrs,n_configured_addrs, "setupinit");

    assert(transport_peers_valid(&st->setup_peers));
    return True;
}

static void transport_setup_msgok(struct site *st, const struct comm_addr *a) {
    if (st->peer_mobile)
	transport_expire_record_peers(st,&st->setup_peers,a,1,"setupmsg");
}
static void transport_data_msgok(struct site *st, const struct comm_addr *a) {
    if (st->peer_mobile)
	transport_expire_record_peers(st,&st->peers,a,1,"datamsg");
}

static int transport_peers_valid(transport_peers *peers) {
    return peers->npeers;
}
static void transport_peers_clear(struct site *st, transport_peers *peers) {
    peers->npeers= 0;
    transport_peers_debug(st,peers,"clear",0,0,0);
}
static void transport_peers_copy(struct site *st, transport_peers *dst,
				 const transport_peers *src) {
    dst->npeers=src->npeers;
    COPY_ARRAY(dst->peers, src->peers, dst->npeers);
    transport_peers_debug(st,dst,"copy",
			  src->npeers, &src->peers->addr, sizeof(*src->peers));
}

static void transport_resolve_complete(struct site *st,
				       const struct comm_addr *addrs,
				       int naddrs) {
    transport_expire_record_peers(st,&st->peers,addrs,naddrs,
				  "resolved data");
    transport_expire_record_peers(st,&st->setup_peers,addrs,naddrs,
				  "resolved setup");
}

static void transport_resolve_complete_tardy(struct site *st,
					     const struct comm_addr *addrs,
					     int naddrs) {
    transport_expire_record_peers(st,&st->peers,addrs,naddrs,
				  "resolved tardily");
}

static void transport_peers__copy_by_mask(transport_peer *out, int *nout_io,
					  unsigned mask,
					  const transport_peers *inp) {
    /* out and in->peers may be the same region, or nonoverlapping */
    const transport_peer *in=inp->peers;
    int slot;
    for (slot=0; slot<inp->npeers; slot++) {
	if (!(mask & (1U << slot)))
	    continue;
	if (!(out==in && slot==*nout_io))
	    COPY_OBJ(out[*nout_io], in[slot]);
	(*nout_io)++;
    }
}

void transport_xmit(struct site *st, transport_peers *peers,
		    struct buffer_if *buf, bool_t candebug) {
    int slot;
    transport_peers_expire(st, peers);
    unsigned failed=0; /* bitmask */
    assert(MAX_PEER_ADDRS < sizeof(unsigned)*CHAR_BIT);

    int nfailed=0;
    for (slot=0; slot<peers->npeers; slot++) {
	transport_peer *peer=&peers->peers[slot];
	bool_t ok = comm_addr_sendmsg(st, &peer->addr, buf);
	if (candebug)
	    dump_packet(st, buf, &peer->addr, False, ok);
	if (!ok) {
	    failed |= 1U << slot;
	    nfailed++;
	}
	if (ok && !st->peer_mobile)
	    break;
    }
    /* Now we need to demote/delete failing addrs: if we are mobile we
     * merely demote them; otherwise we delete them. */
    if (st->local_mobile) {
	unsigned expected = ((1U << nfailed)-1) << (peers->npeers-nfailed);
	/* `expected' has all the failures at the end already */
	if (failed != expected) {
	    int fslot=0;
	    transport_peer failedpeers[nfailed];
	    transport_peers__copy_by_mask(failedpeers, &fslot, failed,peers);
	    assert(fslot == nfailed);
	    int wslot=0;
	    transport_peers__copy_by_mask(peers->peers,&wslot,~failed,peers);
	    assert(wslot+nfailed == peers->npeers);
	    COPY_ARRAY(peers->peers+wslot, failedpeers, nfailed);
	    transport_peers_debug(st,peers,"mobile failure reorder",0,0,0);
	}
    } else {
	if (failed && peers->npeers > 1) {
	    int wslot=0;
	    transport_peers__copy_by_mask(peers->peers,&wslot,~failed,peers);
	    peers->npeers=wslot;
	    transport_peers_debug(st,peers,"non-mobile failure cleanup",0,0,0);
	}
    }
}

/***** END of transport peers declarations *****/
