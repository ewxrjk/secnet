/* site.c - manage communication with a remote network site */

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
    { "default", LOG_SETUP_INIT|LOG_SETUP_TIMEOUT|
      LOG_ACTIVATE_KEY|LOG_TIMEOUT_KEY|LOG_SEC|LOG_ERROR },
    { "all", 0xffffffff },
    { NULL, 0 }
};

struct site {
    closure_t cl;
    struct site_if ops;
/* configuration information */
    string_t localname;
    string_t remotename;
    string_t tunname; /* localname<->remotename by default, used in logs */
    string_t address; /* DNS name for bootstrapping, optional */
    int remoteport; /* Port for bootstrapping, optional */
    struct netlink_if *netlink;
    struct comm_if *comm;
    struct resolver_if *resolver;
    struct log_if *log;
    struct random_if *random;
    struct rsaprivkey_if *privkey;
    struct rsapubkey_if *pubkey;
    struct transform_if *transform;
    struct dh_if *dh;
    struct hash_if *hash;

    uint32_t index; /* Index of this site */
    int32_t setup_retries; /* How many times to send setup packets */
    int32_t setup_retry_interval; /* Initial timeout for setup packets */
    int32_t wait_timeout; /* How long to wait if setup unsuccessful */
    int32_t key_lifetime; /* How long a key lasts once set up */
    int32_t key_renegotiate_time; /* If we see traffic (or a keepalive)
				      after this time, initiate a new
				      key exchange */

    uint8_t *setupsig; /* Expected signature of incoming MSG1 packets */
    int32_t setupsiglen; /* Allows us to discard packets quickly if
			    they are not for us */
    bool_t setup_priority; /* Do we have precedence if both sites emit
			      message 1 simultaneously? */
    uint32_t log_events;

/* runtime information */
    uint32_t state;
    uint64_t now; /* Most recently seen time */

    /* The currently established session */
    uint32_t remote_session_id;
    struct transform_inst_if *current_transform;
    bool_t current_valid;
    uint64_t current_key_timeout; /* End of life of current key */
    uint64_t renegotiate_key_time; /* When we can negotiate a new key */
    struct comm_addr peer; /* Current address of peer */
    bool_t peer_valid; /* Peer address becomes invalid when key times out,
			  but only if we have a DNS name for our peer */

    /* The current key setup protocol exchange.  We can only be
       involved in one of these at a time.  There's a potential for
       denial of service here (the attacker keeps sending a setup
       packet; we keep trying to continue the exchange, and have to
       timeout before we can listen for another setup packet); perhaps
       we should keep a list of 'bad' sources for setup packets. */
    uint32_t setup_session_id;
    struct comm_addr setup_peer;
    uint8_t localN[NONCELEN]; /* Nonces for key exchange */
    uint8_t remoteN[NONCELEN];
    struct buffer_if buffer; /* Current outgoing key exchange packet */
    int32_t retries; /* Number of retries remaining */
    uint64_t timeout; /* Timeout for current state */
    uint8_t *dhsecret;
    uint8_t *sharedsecret;
    struct transform_inst_if *new_transform; /* For key setup/verify */
};

static void slog(struct site *st, uint32_t event, cstring_t msg, ...)
{
    va_list ap;
    char buf[240];
    uint32_t class;

    va_start(ap,msg);

    if (event&st->log_events) {
	switch(event) {
	case LOG_UNEXPECTED: class=M_INFO; break;
	case LOG_SETUP_INIT: class=M_INFO; break;
	case LOG_SETUP_TIMEOUT: class=M_NOTICE; break;
	case LOG_ACTIVATE_KEY: class=M_INFO; break;
	case LOG_TIMEOUT_KEY: class=M_INFO; break;
	case LOG_SEC: class=M_SECURITY; break;
	case LOG_STATE: class=M_DEBUG; break;
	case LOG_DROP: class=M_DEBUG; break;
	case LOG_DUMP: class=M_DEBUG; break;
	case LOG_ERROR: class=M_ERR; break;
	default: class=M_ERR; break;
	}

	vsnprintf(buf,sizeof(buf),msg,ap);
	st->log->log(st->log->st,class,"%s: %s",st->tunname,buf);
    }
    va_end(ap);
}

static void set_link_quality(struct site *st);
static void delete_key(struct site *st, cstring_t reason, uint32_t loglevel);
static bool_t initiate_key_setup(struct site *st, cstring_t reason);
static void enter_state_run(struct site *st);
static bool_t enter_state_resolve(struct site *st);
static bool_t enter_new_state(struct site *st,uint32_t next);
static void enter_state_wait(struct site *st);

#define CHECK_AVAIL(b,l) do { if ((b)->size<(l)) return False; } while(0)
#define CHECK_EMPTY(b) do { if ((b)->size!=0) return False; } while(0)
#define CHECK_TYPE(b,t) do { uint32_t type; \
    CHECK_AVAIL((b),4); \
    type=buf_unprepend_uint32((b)); \
    if (type!=(t)) return False; } while(0)

struct msg {
    uint8_t *hashstart;
    uint32_t dest;
    uint32_t source;
    int32_t remlen;
    uint8_t *remote;
    int32_t loclen;
    uint8_t *local;
    uint8_t *nR;
    uint8_t *nL;
    int32_t pklen;
    char *pk;
    int32_t hashlen;
    int32_t siglen;
    char *sig;
};

/* Build any of msg1 to msg4. msg5 and msg6 are built from the inside
   out using a transform of config data supplied by netlink */
static bool_t generate_msg(struct site *st, uint32_t type, cstring_t what)
{
    void *hst;
    uint8_t *hash;
    string_t dhpub, sig;

    st->retries=st->setup_retries;
    BUF_ALLOC(&st->buffer,what);
    buffer_init(&st->buffer,0);
    buf_append_uint32(&st->buffer,
	(type==LABEL_MSG1?0:st->setup_session_id));
    buf_append_uint32(&st->buffer,st->index);
    buf_append_uint32(&st->buffer,type);
    buf_append_string(&st->buffer,st->localname);
    buf_append_string(&st->buffer,st->remotename);
    memcpy(buf_append(&st->buffer,NONCELEN),st->localN,NONCELEN);
    if (type==LABEL_MSG1) return True;
    memcpy(buf_append(&st->buffer,NONCELEN),st->remoteN,NONCELEN);
    if (type==LABEL_MSG2) return True;

    if (hacky_par_mid_failnow()) return False;

    dhpub=st->dh->makepublic(st->dh->st,st->dhsecret,st->dh->len);
    buf_append_string(&st->buffer,dhpub);
    free(dhpub);
    hash=safe_malloc(st->hash->len, "generate_msg");
    hst=st->hash->init();
    st->hash->update(hst,st->buffer.start,st->buffer.size);
    st->hash->final(hst,hash);
    sig=st->privkey->sign(st->privkey->st,hash,st->hash->len);
    buf_append_string(&st->buffer,sig);
    free(sig);
    free(hash);
    return True;
}

static bool_t unpick_msg(struct site *st, uint32_t type,
			 struct buffer_if *msg, struct msg *m)
{
    m->hashstart=msg->start;
    CHECK_AVAIL(msg,4);
    m->dest=buf_unprepend_uint32(msg);
    CHECK_AVAIL(msg,4);
    m->source=buf_unprepend_uint32(msg);
    CHECK_TYPE(msg,type);
    CHECK_AVAIL(msg,2);
    m->remlen=buf_unprepend_uint16(msg);
    CHECK_AVAIL(msg,m->remlen);
    m->remote=buf_unprepend(msg,m->remlen);
    CHECK_AVAIL(msg,2);
    m->loclen=buf_unprepend_uint16(msg);
    CHECK_AVAIL(msg,m->loclen);
    m->local=buf_unprepend(msg,m->loclen);
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
    CHECK_AVAIL(msg,2);
    m->pklen=buf_unprepend_uint16(msg);
    CHECK_AVAIL(msg,m->pklen);
    m->pk=buf_unprepend(msg,m->pklen);
    m->hashlen=msg->start-m->hashstart;
    CHECK_AVAIL(msg,2);
    m->siglen=buf_unprepend_uint16(msg);
    CHECK_AVAIL(msg,m->siglen);
    m->sig=buf_unprepend(msg,m->siglen);
    CHECK_EMPTY(msg);
    return True;
}

static bool_t check_msg(struct site *st, uint32_t type, struct msg *m,
			cstring_t *error)
{
    if (type==LABEL_MSG1) return True;

    /* Check that the site names and our nonce have been sent
       back correctly, and then store our peer's nonce. */ 
    if (memcmp(m->remote,st->remotename,strlen(st->remotename)!=0)) {
	*error="wrong remote site name";
	return False;
    }
    if (memcmp(m->local,st->localname,strlen(st->localname)!=0)) {
	*error="wrong local site name";
	return False;
    }
    if (memcmp(m->nL,st->localN,NONCELEN)!=0) {
	*error="wrong locally-generated nonce";
	return False;
    }
    if (type==LABEL_MSG2) return True;
    if (memcmp(m->nR,st->remoteN,NONCELEN)!=0) {
	*error="wrong remotely-generated nonce";
	return False;
    }
    if (type==LABEL_MSG3) return True;
    if (type==LABEL_MSG4) return True;
    *error="unknown message type";
    return False;
}

static bool_t generate_msg1(struct site *st)
{
    st->random->generate(st->random->st,NONCELEN,st->localN);
    return generate_msg(st,LABEL_MSG1,"site:MSG1");
}

static bool_t process_msg1(struct site *st, struct buffer_if *msg1,
			   const struct comm_addr *src)
{
    struct msg m;

    /* We've already determined we're in an appropriate state to
       process an incoming MSG1, and that the MSG1 has correct values
       of A and B. */

    if (!unpick_msg(st,LABEL_MSG1,msg1,&m)) return False;

    st->setup_peer=*src;
    st->setup_session_id=m.source;
    memcpy(st->remoteN,m.nR,NONCELEN);
    return True;
}

static bool_t generate_msg2(struct site *st)
{
    st->random->generate(st->random->st,NONCELEN,st->localN);
    return generate_msg(st,LABEL_MSG2,"site:MSG2");
}

static bool_t process_msg2(struct site *st, struct buffer_if *msg2,
			   const struct comm_addr *src)
{
    struct msg m;
    cstring_t err;

    if (!unpick_msg(st,LABEL_MSG2,msg2,&m)) return False;
    if (!check_msg(st,LABEL_MSG2,&m,&err)) {
	slog(st,LOG_SEC,"msg2: %s",err);
	return False;
    }
    st->setup_session_id=m.source;
    memcpy(st->remoteN,m.nR,NONCELEN);
    return True;
}

static bool_t generate_msg3(struct site *st)
{
    /* Now we have our nonce and their nonce. Think of a secret key,
       and create message number 3. */
    st->random->generate(st->random->st,st->dh->len,st->dhsecret);
    return generate_msg(st,LABEL_MSG3,"site:MSG3");
}

static bool_t process_msg3(struct site *st, struct buffer_if *msg3,
			   const struct comm_addr *src)
{
    struct msg m;
    uint8_t *hash;
    void *hst;
    cstring_t err;

    if (!unpick_msg(st,LABEL_MSG3,msg3,&m)) return False;
    if (!check_msg(st,LABEL_MSG3,&m,&err)) {
	slog(st,LOG_SEC,"msg3: %s",err);
	return False;
    }

    /* Check signature and store g^x mod m */
    hash=safe_malloc(st->hash->len, "process_msg3");
    hst=st->hash->init();
    st->hash->update(hst,m.hashstart,m.hashlen);
    st->hash->final(hst,hash);
    /* Terminate signature with a '0' - cheating, but should be ok */
    m.sig[m.siglen]=0;
    if (!st->pubkey->check(st->pubkey->st,hash,st->hash->len,m.sig)) {
	slog(st,LOG_SEC,"msg3 signature failed check!");
	free(hash);
	return False;
    }
    free(hash);

    /* Terminate their DH public key with a '0' */
    m.pk[m.pklen]=0;
    /* Invent our DH secret key */
    st->random->generate(st->random->st,st->dh->len,st->dhsecret);

    /* Generate the shared key */
    st->dh->makeshared(st->dh->st,st->dhsecret,st->dh->len,m.pk,
		       st->sharedsecret,st->transform->keylen);

    /* Set up the transform */
    st->new_transform->setkey(st->new_transform->st,st->sharedsecret,
			      st->transform->keylen);

    return True;
}

static bool_t generate_msg4(struct site *st)
{
    /* We have both nonces, their public key and our private key. Generate
       our public key, sign it and send it to them. */
    return generate_msg(st,LABEL_MSG4,"site:MSG4");
}

static bool_t process_msg4(struct site *st, struct buffer_if *msg4,
			   const struct comm_addr *src)
{
    struct msg m;
    uint8_t *hash;
    void *hst;
    cstring_t err;

    if (!unpick_msg(st,LABEL_MSG4,msg4,&m)) return False;
    if (!check_msg(st,LABEL_MSG4,&m,&err)) {
	slog(st,LOG_SEC,"msg4: %s",err);
	return False;
    }
    
    /* Check signature and store g^x mod m */
    hash=safe_malloc(st->hash->len, "process_msg4");
    hst=st->hash->init();
    st->hash->update(hst,m.hashstart,m.hashlen);
    st->hash->final(hst,hash);
    /* Terminate signature with a '0' - cheating, but should be ok */
    m.sig[m.siglen]=0;
    if (!st->pubkey->check(st->pubkey->st,hash,st->hash->len,m.sig)) {
	slog(st,LOG_SEC,"msg4 signature failed check!");
	free(hash);
	return False;
    }
    free(hash);

    /* Terminate their DH public key with a '0' */
    m.pk[m.pklen]=0;
    /* Generate the shared key */
    st->dh->makeshared(st->dh->st,st->dhsecret,st->dh->len,m.pk,
		       st->sharedsecret,st->transform->keylen);
    /* Set up the transform */
    st->new_transform->setkey(st->new_transform->st,st->sharedsecret,
			      st->transform->keylen);

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

static bool_t generate_msg5(struct site *st)
{
    cstring_t transform_err;

    BUF_ALLOC(&st->buffer,"site:MSG5");
    /* We are going to add four words to the message */
    buffer_init(&st->buffer,st->transform->max_start_pad+(4*4));
    /* Give the netlink code an opportunity to put its own stuff in the
       message (configuration information, etc.) */
    st->netlink->output_config(st->netlink->st,&st->buffer);
    buf_prepend_uint32(&st->buffer,LABEL_MSG5);
    st->new_transform->forwards(st->new_transform->st,&st->buffer,
				&transform_err);
    buf_prepend_uint32(&st->buffer,LABEL_MSG5);
    buf_prepend_uint32(&st->buffer,st->index);
    buf_prepend_uint32(&st->buffer,st->setup_session_id);

    st->retries=st->setup_retries;
    return True;
}

static bool_t process_msg5(struct site *st, struct buffer_if *msg5,
			   const struct comm_addr *src)
{
    struct msg0 m;
    cstring_t transform_err;

    if (!unpick_msg0(st,msg5,&m)) return False;

    if (st->new_transform->reverse(st->new_transform->st,
				   msg5,&transform_err)) {
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
    if (!st->netlink->check_config(st->netlink->st,msg5)) {
	slog(st,LOG_SEC,"MSG5/PING packet contained bad netlink config");
	return False;
    }
    CHECK_EMPTY(msg5);
    return True;
}

static bool_t generate_msg6(struct site *st)
{
    cstring_t transform_err;

    BUF_ALLOC(&st->buffer,"site:MSG6");
    /* We are going to add four words to the message */
    buffer_init(&st->buffer,st->transform->max_start_pad+(4*4));
    /* Give the netlink code an opportunity to put its own stuff in the
       message (configuration information, etc.) */
    st->netlink->output_config(st->netlink->st,&st->buffer);
    buf_prepend_uint32(&st->buffer,LABEL_MSG6);
    st->new_transform->forwards(st->new_transform->st,&st->buffer,
				&transform_err);
    buf_prepend_uint32(&st->buffer,LABEL_MSG6);
    buf_prepend_uint32(&st->buffer,st->index);
    buf_prepend_uint32(&st->buffer,st->setup_session_id);

    st->retries=1; /* Peer will retransmit MSG5 if this packet gets lost */
    return True;
}

static bool_t process_msg6(struct site *st, struct buffer_if *msg6,
			   const struct comm_addr *src)
{
    struct msg0 m;
    cstring_t transform_err;

    if (!unpick_msg0(st,msg6,&m)) return False;

    if (st->new_transform->reverse(st->new_transform->st,
				   msg6,&transform_err)) {
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
    if (!st->netlink->check_config(st->netlink->st,msg6)) {
	slog(st,LOG_SEC,"MSG6/PONG packet contained bad netlink config");
	return False;
    }
    CHECK_EMPTY(msg6);
    return True;
}

static bool_t process_msg0(struct site *st, struct buffer_if *msg0,
			   const struct comm_addr *src)
{
    struct msg0 m;
    cstring_t transform_err;
    uint32_t type;

    if (!st->current_valid) {
	slog(st,LOG_DROP,"incoming message but no current key -> dropping");
	return initiate_key_setup(st,"incoming message but no current key");
    }

    if (!unpick_msg0(st,msg0,&m)) return False;

    if (st->current_transform->reverse(st->current_transform->st,
				       msg0,&transform_err)) {
	/* There's a problem */
	slog(st,LOG_SEC,"transform: %s",transform_err);
	return initiate_key_setup(st,"incoming message would not decrypt");
    }
    CHECK_AVAIL(msg0,4);
    type=buf_unprepend_uint32(msg0);
    switch(type) {
    case LABEL_MSG7:
	/* We must forget about the current session. */
	delete_key(st,"request from peer",LOG_SEC);
	return True;
    case LABEL_MSG9:
	/* Deliver to netlink layer */
	st->netlink->deliver(st->netlink->st,msg0);
	return True;
    default:
	slog(st,LOG_SEC,"incoming encrypted message of type %08x "
	     "(unknown)",type);
	break;
    }
    return False;
}

static void dump_packet(struct site *st, struct buffer_if *buf,
			const struct comm_addr *addr, bool_t incoming)
{
    uint32_t dest=ntohl(*(uint32_t *)buf->start);
    uint32_t source=ntohl(*(uint32_t *)(buf->start+4));
    uint32_t msgtype=ntohl(*(uint32_t *)(buf->start+8));

    if (st->log_events & LOG_DUMP)
	slilog(st->log,M_DEBUG,"%s: %s: %08x<-%08x: %08x:",
	       st->tunname,incoming?"incoming":"outgoing",
	       dest,source,msgtype);
}

static uint32_t site_status(void *st)
{
    return 0;
}

static bool_t send_msg(struct site *st)
{
    if (st->retries>0) {
	dump_packet(st,&st->buffer,&st->setup_peer,False);
	st->comm->sendmsg(st->comm->st,&st->buffer,&st->setup_peer);
	st->timeout=st->now+st->setup_retry_interval;
	st->retries--;
	return True;
    } else {
	slog(st,LOG_SETUP_TIMEOUT,"timed out sending key setup packet "
	    "(in state %s)",state_name(st->state));
	enter_state_wait(st);
	return False;
    }
}

static void site_resolve_callback(void *sst, struct in_addr *address)
{
    struct site *st=sst;

    if (st->state!=SITE_RESOLVE) {
	slog(st,LOG_UNEXPECTED,"site_resolve_callback called unexpectedly");
	return;
    }
    if (address) {
	memset(&st->setup_peer,0,sizeof(st->setup_peer));
	st->setup_peer.comm=st->comm;
	st->setup_peer.sin.sin_family=AF_INET;
	st->setup_peer.sin.sin_port=htons(st->remoteport);
	st->setup_peer.sin.sin_addr=*address;
	enter_new_state(st,SITE_SENTMSG1);
    } else {
	/* Resolution failed */
	slog(st,LOG_ERROR,"resolution of %s failed",st->address);
	enter_state_run(st);
    }
}

static bool_t initiate_key_setup(struct site *st, cstring_t reason)
{
    if (st->state!=SITE_RUN) return False;
    slog(st,LOG_SETUP_INIT,"initiating key exchange (%s)",reason);
    if (st->address) {
	slog(st,LOG_SETUP_INIT,"resolving peer address");
	return enter_state_resolve(st);
    } else if (st->peer_valid) {
	slog(st,LOG_SETUP_INIT,"using old peer address");
	st->setup_peer=st->peer;
	return enter_new_state(st,SITE_SENTMSG1);
    }
    slog(st,LOG_SETUP_INIT,"key exchange failed: no address for peer");
    return False;
}

static void activate_new_key(struct site *st)
{
    struct transform_inst_if *t;

    /* We have two transform instances, which we swap between active
       and setup */
    t=st->current_transform;
    st->current_transform=st->new_transform;
    st->new_transform=t;

    t->delkey(t->st);
    st->timeout=0;
    st->current_valid=True;
    st->current_key_timeout=st->now+st->key_lifetime;
    st->renegotiate_key_time=st->now+st->key_renegotiate_time;
    st->peer=st->setup_peer;
    st->peer_valid=True;
    st->remote_session_id=st->setup_session_id;

    slog(st,LOG_ACTIVATE_KEY,"new key activated");
    enter_state_run(st);
}

static void delete_key(struct site *st, cstring_t reason, uint32_t loglevel)
{
    if (st->current_valid) {
	slog(st,loglevel,"session closed (%s)",reason);

	st->current_valid=False;
	st->current_transform->delkey(st->current_transform->st);
	st->current_key_timeout=0;
	set_link_quality(st);
    }
}

static void state_assert(struct site *st, bool_t ok)
{
    if (!ok) fatal("site:state_assert");
}

static void enter_state_stop(struct site *st)
{
    st->state=SITE_STOP;
    st->timeout=0;
    delete_key(st,"entering state STOP",LOG_TIMEOUT_KEY);
    st->new_transform->delkey(st->new_transform->st);
}

static void set_link_quality(struct site *st)
{
    uint32_t quality;
    if (st->current_valid)
	quality=LINK_QUALITY_UP;
    else if (st->state==SITE_WAIT || st->state==SITE_STOP)
	quality=LINK_QUALITY_DOWN;
    else if (st->address)
	quality=LINK_QUALITY_DOWN_CURRENT_ADDRESS;
    else if (st->peer_valid)
	quality=LINK_QUALITY_DOWN_STALE_ADDRESS;
    else
	quality=LINK_QUALITY_DOWN;

    st->netlink->set_quality(st->netlink->st,quality);
}

static void enter_state_run(struct site *st)
{
    slog(st,LOG_STATE,"entering state RUN");
    st->state=SITE_RUN;
    st->timeout=0;

    st->setup_session_id=0;
    memset(&st->setup_peer,0,sizeof(st->setup_peer));
    memset(st->localN,0,NONCELEN);
    memset(st->remoteN,0,NONCELEN);
    st->new_transform->delkey(st->new_transform->st);
    memset(st->dhsecret,0,st->dh->len);
    memset(st->sharedsecret,0,st->transform->keylen);
    set_link_quality(st);
}

static bool_t enter_state_resolve(struct site *st)
{
    state_assert(st,st->state==SITE_RUN);
    slog(st,LOG_STATE,"entering state RESOLVE");
    st->state=SITE_RESOLVE;
    st->resolver->request(st->resolver->st,st->address,
			  site_resolve_callback,st);
    return True;
}

static bool_t enter_new_state(struct site *st, uint32_t next)
{
    bool_t (*gen)(struct site *st);
    int r;

    slog(st,LOG_STATE,"entering state %s",state_name(next));
    switch(next) {
    case SITE_SENTMSG1:
	state_assert(st,st->state==SITE_RUN || st->state==SITE_RESOLVE);
	gen=generate_msg1;
	break;
    case SITE_SENTMSG2:
	state_assert(st,st->state==SITE_RUN || st->state==SITE_RESOLVE ||
		     st->state==SITE_SENTMSG1 || st->state==SITE_WAIT);
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

    r= gen(st) && send_msg(st);

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

    if (st->current_valid && st->peer_valid && st->buffer.free) {
	BUF_ALLOC(&st->buffer,"site:MSG7");
	buffer_init(&st->buffer,st->transform->max_start_pad+(4*3));
	buf_append_uint32(&st->buffer,LABEL_MSG7);
	buf_append_string(&st->buffer,reason);
	st->current_transform->forwards(st->current_transform->st,
					&st->buffer, &transform_err);
	buf_prepend_uint32(&st->buffer,LABEL_MSG0);
	buf_prepend_uint32(&st->buffer,st->index);
	buf_prepend_uint32(&st->buffer,st->remote_session_id);
	dump_packet(st,&st->buffer,&st->peer,False);
	st->comm->sendmsg(st->comm->st,&st->buffer,&st->peer);
	BUF_FREE(&st->buffer);
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
    st->timeout=st->now+st->wait_timeout;
    st->state=SITE_WAIT;
    set_link_quality(st);
    BUF_FREE(&st->buffer); /* will have had an outgoing packet in it */
    /* XXX Erase keys etc. */
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

    *nfds_io=0; /* We don't use any file descriptors */
    st->now=*now;

    /* Work out when our next timeout is. The earlier of 'timeout' or
       'current_key_timeout'. A stored value of '0' indicates no timeout
       active. */
    site_settimeout(st->timeout, timeout_io);
    site_settimeout(st->current_key_timeout, timeout_io);

    return 0; /* success */
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
    if (st->current_key_timeout && *now>st->current_key_timeout) {
	delete_key(st,"maximum key life exceeded",LOG_TIMEOUT_KEY);
    }
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

    /* In all other states we consider delivering the packet if we have
       a valid key and a valid address to send it to. */
    if (st->current_valid && st->peer_valid) {
	/* Transform it and send it */
	if (buf->size>0) {
	    buf_prepend_uint32(buf,LABEL_MSG9);
	    st->current_transform->forwards(st->current_transform->st,
					    buf, &transform_err);
	    buf_prepend_uint32(buf,LABEL_MSG0);
	    buf_prepend_uint32(buf,st->index);
	    buf_prepend_uint32(buf,st->remote_session_id);
	    st->comm->sendmsg(st->comm->st,buf,&st->peer);
	}
	BUF_FREE(buf);
	/* See whether we should start negotiating a new key */
	if (st->now > st->renegotiate_key_time)
	    initiate_key_setup(st,"outgoing packet in renegotiation window");
	return;
    }

    slog(st,LOG_DROP,"discarding outgoing packet of size %d",buf->size);
    BUF_FREE(buf);
    initiate_key_setup(st,"outgoing packet");
}

/* This function is called by the communication device to deliver
   packets from our peers. */
static bool_t site_incoming(void *sst, struct buffer_if *buf,
			    const struct comm_addr *source)
{
    struct site *st=sst;
    uint32_t dest=ntohl(*(uint32_t *)buf->start);

    if (dest==0) {
	/* It could be for any site - it should have LABEL_MSG1 and
	   might have our name and our peer's name in it */
	if (buf->size<(st->setupsiglen+8+NONCELEN)) return False;
	if (memcmp(buf->start+8,st->setupsig,st->setupsiglen)==0) {
	    /* It's addressed to us. Decide what to do about it. */
	    dump_packet(st,buf,source,True);
	    if (st->state==SITE_RUN || st->state==SITE_RESOLVE ||
		st->state==SITE_WAIT) {
		/* We should definitely process it */
		if (process_msg1(st,buf,source)) {
		    slog(st,LOG_SETUP_INIT,"key setup initiated by peer");
		    enter_new_state(st,SITE_SENTMSG2);
		} else {
		    slog(st,LOG_ERROR,"failed to process incoming msg1");
		}
		BUF_FREE(buf);
		return True;
	    } else if (st->state==SITE_SENTMSG1) {
		/* We've just sent a message 1! They may have crossed on
		   the wire. If we have priority then we ignore the
		   incoming one, otherwise we process it as usual. */
		if (st->setup_priority) {
		    BUF_FREE(buf);
		    slog(st,LOG_DUMP,"crossed msg1s; we are higher "
			 "priority => ignore incoming msg1");
		    return True;
		} else {
		    slog(st,LOG_DUMP,"crossed msg1s; we are lower "
			 "priority => use incoming msg1");
		    if (process_msg1(st,buf,source)) {
			BUF_FREE(&st->buffer); /* Free our old message 1 */
			enter_new_state(st,SITE_SENTMSG2);
		    } else {
			slog(st,LOG_ERROR,"failed to process an incoming "
			     "crossed msg1 (we have low priority)");
		    }
		    BUF_FREE(buf);
		    return True;
		}
	    }
	    /* The message 1 was received at an unexpected stage of the
	       key setup. XXX POLICY - what do we do? */
	    slog(st,LOG_UNEXPECTED,"unexpected incoming message 1");
	    BUF_FREE(buf);
	    return True;
	}
	return False; /* Not for us. */
    }
    if (dest==st->index) {
	/* Explicitly addressed to us */
	uint32_t msgtype=ntohl(get_uint32(buf->start+8));
	if (msgtype!=LABEL_MSG0) dump_packet(st,buf,source,True);
	switch (msgtype) {
	case 0: /* NAK */
	    /* If the source is our current peer then initiate a key setup,
	       because our peer's forgotten the key */
	    if (get_uint32(buf->start+4)==st->remote_session_id) {
		initiate_key_setup(st,"received a NAK");
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
		slog(st,LOG_UNEXPECTED,"unexpected MSG2");
	    } else if (process_msg2(st,buf,source))
		enter_new_state(st,SITE_SENTMSG3);
	    else {
		slog(st,LOG_SEC,"invalid MSG2");
	    }
	    break;
	case LABEL_MSG3:
	    /* Setup packet: expected only in state SENTMSG2 */
	    if (st->state!=SITE_SENTMSG2) {
		slog(st,LOG_UNEXPECTED,"unexpected MSG3");
	    } else if (process_msg3(st,buf,source))
		enter_new_state(st,SITE_SENTMSG4);
	    else {
		slog(st,LOG_SEC,"invalid MSG3");
	    }
	    break;
	case LABEL_MSG4:
	    /* Setup packet: expected only in state SENTMSG3 */
	    if (st->state!=SITE_SENTMSG3) {
		slog(st,LOG_UNEXPECTED,"unexpected MSG4");
	    } else if (process_msg4(st,buf,source))
		enter_new_state(st,SITE_SENTMSG5);
	    else {
		slog(st,LOG_SEC,"invalid MSG4");
	    }
	    break;
	case LABEL_MSG5:
	    /* Setup packet: expected only in state SENTMSG4 */
	    /* (may turn up in state RUN if our return MSG6 was lost
	       and the new key has already been activated. In that
	       case we should treat it as an ordinary PING packet. We
	       can't pass it to process_msg5() because the
	       new_transform will now be unkeyed. XXX) */
	    if (st->state!=SITE_SENTMSG4) {
		slog(st,LOG_UNEXPECTED,"unexpected MSG5");
	    } else if (process_msg5(st,buf,source)) {
		enter_new_state(st,SITE_RUN);
	    } else {
		slog(st,LOG_SEC,"invalid MSG5");
	    }
	    break;
	case LABEL_MSG6:
	    /* Setup packet: expected only in state SENTMSG5 */
	    if (st->state!=SITE_SENTMSG5) {
		slog(st,LOG_UNEXPECTED,"unexpected MSG6");
	    } else if (process_msg6(st,buf,source)) {
		BUF_FREE(&st->buffer); /* Free message 5 */
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

static list_t *site_apply(closure_t *self, struct cloc loc, dict_t *context,
			  list_t *args)
{
    static uint32_t index_sequence;
    struct site *st;
    item_t *item;
    dict_t *dict;

    st=safe_malloc(sizeof(*st),"site_apply");

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
    /* Sanity check (which also allows the 'sites' file to include
       site() closures for all sites including our own): refuse to
       talk to ourselves */
    if (strcmp(st->localname,st->remotename)==0) {
	Message(M_DEBUG,"site %s: local-name==name -> ignoring this site\n",
		st->localname);
	free(st);
	return NULL;
    }
    assert(index_sequence < 0xffffffffUL);
    st->index = ++index_sequence;
    st->netlink=find_cl_if(dict,"link",CL_NETLINK,True,"site",loc);
    st->comm=find_cl_if(dict,"comm",CL_COMM,True,"site",loc);
    st->resolver=find_cl_if(dict,"resolver",CL_RESOLVER,True,"site",loc);
    st->log=find_cl_if(dict,"log",CL_LOG,True,"site",loc);
    st->random=find_cl_if(dict,"random",CL_RANDOMSRC,True,"site",loc);

    st->privkey=find_cl_if(dict,"local-key",CL_RSAPRIVKEY,True,"site",loc);
    st->address=dict_read_string(dict, "address", False, "site", loc);
    if (st->address)
	st->remoteport=dict_read_number(dict,"port",True,"site",loc,0);
    else st->remoteport=0;
    st->pubkey=find_cl_if(dict,"key",CL_RSAPUBKEY,True,"site",loc);

    st->transform=
	find_cl_if(dict,"transform",CL_TRANSFORM,True,"site",loc);

    st->dh=find_cl_if(dict,"dh",CL_DH,True,"site",loc);
    st->hash=find_cl_if(dict,"hash",CL_HASH,True,"site",loc);

#define DEFAULT(D) DEFAULT_##D
#define CFG_NUMBER(k,D) dict_read_number(dict,(k),False,"site",loc,DEFAULT(D));

    st->key_lifetime=         CFG_NUMBER("key-lifetime",  KEY_LIFETIME);
    st->setup_retries=        CFG_NUMBER("setup-retries", SETUP_RETRIES);
    st->setup_retry_interval= CFG_NUMBER("setup-timeout", SETUP_RETRY_INTERVAL);
    st->wait_timeout=         CFG_NUMBER("wait-time",     WAIT_TIME);

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

    st->tunname=safe_malloc(strlen(st->localname)+strlen(st->remotename)+5,
			    "site_apply");
    sprintf(st->tunname,"%s<->%s",st->localname,st->remotename);

    /* The information we expect to see in incoming messages of type 1 */
    /* fixme: lots of unchecked overflows here, but the results are only
       corrupted packets rather than undefined behaviour */
    st->setupsiglen=strlen(st->remotename)+strlen(st->localname)+8;
    st->setupsig=safe_malloc(st->setupsiglen,"site_apply");
    put_uint32(st->setupsig+0,LABEL_MSG1);
    put_uint16(st->setupsig+4,strlen(st->remotename));
    memcpy(&st->setupsig[6],st->remotename,strlen(st->remotename));
    put_uint16(st->setupsig+(6+strlen(st->remotename)),strlen(st->localname));
    memcpy(&st->setupsig[8+strlen(st->remotename)],st->localname,
	   strlen(st->localname));
    st->setup_priority=(strcmp(st->localname,st->remotename)>0);

    buffer_new(&st->buffer,SETUP_BUFFER_LEN);

    /* We are interested in poll(), but only for timeouts. We don't have
       any fds of our own. */
    register_for_poll(st, site_beforepoll, site_afterpoll, 0, "site");
    st->timeout=0;

    st->current_valid=False;
    st->current_key_timeout=0;
    st->peer_valid=False;
    /* XXX mlock these */
    st->dhsecret=safe_malloc(st->dh->len,"site:dhsecret");
    st->sharedsecret=safe_malloc(st->transform->keylen,"site:sharedsecret");

    /* We need to register the remote networks with the netlink device */
    st->netlink->reg(st->netlink->st, site_outgoing, st,
		     st->transform->max_start_pad+(4*4)+
		     st->comm->min_start_pad,
		     st->transform->max_end_pad+st->comm->min_end_pad);
    
    st->comm->request_notify(st->comm->st, st, site_incoming);

    st->current_transform=st->transform->create(st->transform->st);
    st->new_transform=st->transform->create(st->transform->st);

    enter_state_stop(st);

    add_hook(PHASE_SHUTDOWN,site_phase_hook,st);

    return new_closure(&st->cl);
}

void site_module(dict_t *dict)
{
    add_closure(dict,"site",site_apply);
}
