/* site.c - manage communication with a remote network site */

#include "secnet.h"
#include <stdio.h>
/* MBM asserts the next one is needed for compilation under BSD. */
#include <sys/socket.h>

#include <sys/mman.h>
#include "util.h"
#include "unaligned.h"

#define SETUP_BUFFER_LEN 2048

#define DEFAULT_KEY_LIFETIME 3600000
#define DEFAULT_SETUP_RETRIES 5
#define DEFAULT_SETUP_TIMEOUT 1000
#define DEFAULT_WAIT_TIME 10000

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

#if 0
static string_t state_name(uint32_t state)
{
    switch (state) {
    case 0: return "SITE_STOP";
    case 1: return "SITE_RUN";
    case 2: return "SITE_RESOLVE";
    case 3: return "SITE_SENTMSG1";
    case 4: return "SITE_SENTMSG2";
    case 5: return "SITE_SENTMSG3";
    case 6: return "SITE_SENTMSG4";
    case 7: return "SITE_SENTMSG5";
    case 8: return "SITE_WAIT";
    default: return "*bad state*";
    }
}
#endif /* 0 */

#define LABEL_MSG0 0x00020200
#define LABEL_MSG1 0x01010101
#define LABEL_MSG2 0x02020202
#define LABEL_MSG3 0x03030303
#define LABEL_MSG4 0x04040404
#define LABEL_MSG5 0x05050505
#define LABEL_MSG6 0x06060606
#define LABEL_MSG7 0x07070707
#define LABEL_MSG8 0x08080808
#define LABEL_MSG9 0x09090909

#define NONCELEN 8

#define LOG_UNEXPECTED    0x00000001
#define LOG_SETUP_INIT    0x00000002
#define LOG_SETUP_TIMEOUT 0x00000004
#define LOG_ACTIVATE_KEY  0x00000008
#define LOG_TIMEOUT_KEY   0x00000010
#define LOG_SEC      0x00000020
#define LOG_STATE         0x00000040
#define LOG_DROP          0x00000080
#define LOG_DUMP          0x00000100
#define LOG_ERROR         0x00000400

struct site {
    closure_t cl;
    struct site_if ops;
/* configuration information */
    string_t localname;
    string_t remotename;
    string_t tunname; /* localname<->remotename by default */
    string_t address; /* DNS name for bootstrapping, optional */
    int remoteport;
    struct netlink_if *netlink;
    struct comm_if *comm;
    struct resolver_if *resolver;
    struct log_if *log;
    struct random_if *random;
    struct rsaprivkey_if *privkey;
    struct subnet_list remotenets;
    struct rsapubkey_if *pubkey;
    struct transform_if *transform;
    struct dh_if *dh;
    struct hash_if *hash;
    void *netlink_cid;

    uint32_t setup_retries; /* How many times to send setup packets */
    uint32_t setup_timeout; /* Initial timeout for setup packets */
    uint32_t wait_timeout; /* How long to wait if setup unsuccessful */
    uint32_t key_lifetime; /* How long a key lasts once set up */

    uint8_t *setupsig; /* Expected signature of incoming MSG1 packets */
    uint32_t setupsiglen; /* Allows us to discard packets quickly if
			     they are not for us */
    bool_t setup_priority; /* Do we have precedence if both sites emit
			      message 1 simultaneously? */
    uint32_t log_events;

/* runtime information */
    uint32_t state;
    uint64_t now; /* Most recently seen time */

    uint32_t remote_session_id;
    struct transform_inst_if *current_transform;
    bool_t current_valid;
    uint64_t current_key_timeout; /* End of life of current key */
    struct sockaddr_in peer; /* Current address of peer */
    bool_t peer_valid; /* Peer address becomes invalid when key times out,
			  but only if we have a DNS name for our peer */

    uint32_t setup_session_id;
    struct sockaddr_in setup_peer;
    uint8_t localN[NONCELEN]; /* Nonces for key exchange */
    uint8_t remoteN[NONCELEN];
    struct buffer_if buffer; /* Current outgoing key exchange packet */
    uint32_t retries; /* Number of retries remaining */
    uint64_t timeout; /* Timeout for current state */
    uint8_t *dhsecret;
    uint8_t *sharedsecret;

    struct transform_inst_if *new_transform; /* For key setup/verify */
};

static void slog(struct site *st, uint32_t event, string_t msg, ...)
{
    va_list ap;
    uint8_t buf[240];

    va_start(ap,msg);

    if (event&st->log_events) {
	vsnprintf(buf,240,msg,ap);
	st->log->log(st->log->st,0,"%s: %s",st->tunname,buf);
    }
    va_end(ap);
}

static void enter_state_run(struct site *st);
static bool_t enter_state_resolve(struct site *st);
static bool_t enter_state_sentmsg1(struct site *st);
static bool_t enter_state_sentmsg2(struct site *st);
static bool_t enter_state_sentmsg3(struct site *st);
static bool_t enter_state_sentmsg4(struct site *st);
static bool_t enter_state_sentmsg5(struct site *st);
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
    uint32_t remlen;
    uint8_t *remote;
    uint32_t loclen;
    uint8_t *local;
    uint8_t *nR;
    uint8_t *nL;
    uint32_t pklen;
    uint8_t *pk;
    uint32_t hashlen;
    uint32_t siglen;
    uint8_t *sig;
};

/* Build any of msg1 to msg4. msg5 and msg6 are built from the inside out
   using a transform. */
static bool_t generate_msg(struct site *st, uint32_t type, string_t what)
{
    void *hst;
    uint8_t *hash=alloca(st->hash->len);
    string_t dhpub, sig;

    st->retries=st->setup_retries;
    BUF_ALLOC(&st->buffer,what);
    buffer_init(&st->buffer,0);
    buf_append_uint32(&st->buffer,
	(type==LABEL_MSG1?0:st->setup_session_id));
    buf_append_uint32(&st->buffer,(uint32_t)st);
    buf_append_uint32(&st->buffer,type);
    buf_append_string(&st->buffer,st->localname);
    buf_append_string(&st->buffer,st->remotename);
    memcpy(buf_append(&st->buffer,NONCELEN),st->localN,NONCELEN);
    if (type==LABEL_MSG1) return True;
    memcpy(buf_append(&st->buffer,NONCELEN),st->remoteN,NONCELEN);
    if (type==LABEL_MSG2) return True;
    dhpub=st->dh->makepublic(st->dh->st,st->dhsecret,st->dh->len);
    buf_append_string(&st->buffer,dhpub);
    free(dhpub);
    hst=st->hash->init();
    st->hash->update(hst,st->buffer.start,st->buffer.size);
    st->hash->final(hst,hash);
    sig=st->privkey->sign(st->privkey->st,hash,st->hash->len);
    buf_append_string(&st->buffer,sig);
    free(sig);
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

static bool_t generate_msg1(struct site *st)
{
    st->random->generate(st->random->st,NONCELEN,st->localN);
    return generate_msg(st,LABEL_MSG1,"site:MSG1");
}

static bool_t process_msg1(struct site *st, struct buffer_if *msg1,
			   struct sockaddr_in *src)
{
    struct msg m;

    /* We've already determined we're in an appropriate state to
       process an incoming MSG1, and that the MSG1 has correct values
       of A and B. */

    if (!unpick_msg(st,LABEL_MSG1,msg1,&m)) return False;

    /* XXX save src as our peer address here? */
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
			   struct sockaddr_in *src)
{
    struct msg m;

    if (!unpick_msg(st,LABEL_MSG2,msg2,&m)) return False;

    /* Check that the site names and our nonce have been sent
       back correctly, and then store our peer's nonce. */ 
    if (memcmp(m.remote,st->remotename,strlen(st->remotename)!=0)) {
	slog(st,LOG_SEC,"msg2: bad B (remote site name)");
	return False;
    }
    if (memcmp(m.local,st->localname,strlen(st->localname)!=0)) {
	slog(st,LOG_SEC,"msg2: bad A (local site name)");
	return False;
    }
    if (memcmp(m.nL,st->localN,NONCELEN)!=0) {
	slog(st,LOG_SEC,"msg2: bad nA (locally generated nonce)");
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
			   struct sockaddr_in *src)
{
    struct msg m;
    uint8_t *hash=alloca(st->hash->len);
    void *hst;

    if (!unpick_msg(st,LABEL_MSG3,msg3,&m)) return False;

    /* Check that the site names and nonces have been sent back
       correctly */
    if (memcmp(m.remote,st->remotename,strlen(st->remotename)!=0)) {
	slog(st,LOG_SEC,"msg3: bad A (remote site name)");
	return False;
    }
    if (memcmp(m.local,st->localname,strlen(st->localname)!=0)) {
	slog(st,LOG_SEC,"msg3: bad B (local site name)");
	return False;
    }
    if (memcmp(m.nR,st->remoteN,NONCELEN)!=0) {
	slog(st,LOG_SEC,"msg3: bad nA (remotely generated nonce)");
	return False;
    }
    if (memcmp(m.nL,st->localN,NONCELEN)!=0) {
	slog(st,LOG_SEC,"msg3: bad nB (locally generated nonce)");
	return False;
    }
    
    /* Check signature and store g^x mod m */
    hst=st->hash->init();
    st->hash->update(hst,m.hashstart,m.hashlen);
    st->hash->final(hst,hash);
    /* Terminate signature with a '0' - cheating, but should be ok */
    m.sig[m.siglen]=0;
    if (!st->pubkey->check(st->pubkey->st,hash,st->hash->len,m.sig)) {
	slog(st,LOG_SEC,"msg3 signature failed check!");
	return False;
    }

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
			   struct sockaddr_in *src)
{
    struct msg m;
    uint8_t *hash=alloca(st->hash->len);
    void *hst;

    if (!unpick_msg(st,LABEL_MSG4,msg4,&m)) return False;

    /* Check that the site names and nonces have been sent back
       correctly */
    if (memcmp(m.remote,st->remotename,strlen(st->remotename)!=0)) {
	slog(st,LOG_SEC,"msg4: bad B (remote site name)");
	return False;
    }
    if (memcmp(m.local,st->localname,strlen(st->localname)!=0)) {
	slog(st,LOG_SEC,"msg4: bad A (local site name)");
	return False;
    }
    if (memcmp(m.nR,st->remoteN,NONCELEN)!=0) {
	slog(st,LOG_SEC,"msg4: bad nB (remotely generated nonce)");
	return False;
    }
    if (memcmp(m.nL,st->localN,NONCELEN)!=0) {
	slog(st,LOG_SEC,"msg4: bad nA (locally generated nonce)");
	return False;
    }
    
    /* Check signature and store g^x mod m */
    hst=st->hash->init();
    st->hash->update(hst,m.hashstart,m.hashlen);
    st->hash->final(hst,hash);
    /* Terminate signature with a '0' - cheating, but should be ok */
    m.sig[m.siglen]=0;
    if (!st->pubkey->check(st->pubkey->st,hash,st->hash->len,m.sig)) {
	slog(st,LOG_SEC,"msg4 signature failed check!");
	return False;
    }

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

static bool_t generate_msg5(struct site *st)
{
    string_t transform_err;

    BUF_ALLOC(&st->buffer,"site:MSG5");
    /* We are going to add three words to the transformed message */
    buffer_init(&st->buffer,st->transform->max_start_pad+(4*3));
    buf_append_uint32(&st->buffer,LABEL_MSG5);
    st->new_transform->forwards(st->new_transform->st,&st->buffer,
				&transform_err);
    buf_prepend_uint32(&st->buffer,LABEL_MSG5);
    buf_prepend_uint32(&st->buffer,(uint32_t)st);
    buf_prepend_uint32(&st->buffer,st->setup_session_id);

    st->retries=st->setup_retries;
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

static bool_t process_msg5(struct site *st, struct buffer_if *msg5,
			   struct sockaddr_in *src)
{
    struct msg0 m;
    string_t transform_err;

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
	slog(st,LOG_SEC,"MSG5/PING packet contained invalid data");
	return False;
    }
    CHECK_EMPTY(msg5);
    return True;
}

static bool_t generate_msg6(struct site *st)
{
    string_t transform_err;

    BUF_ALLOC(&st->buffer,"site:MSG6");
    /* We are going to add three words to the transformed message */
    buffer_init(&st->buffer,st->transform->max_start_pad+(4*3));
    buf_append_uint32(&st->buffer,LABEL_MSG6);
    st->new_transform->forwards(st->new_transform->st,&st->buffer,
				&transform_err);
    buf_prepend_uint32(&st->buffer,LABEL_MSG6);
    buf_prepend_uint32(&st->buffer,(uint32_t)st);
    buf_prepend_uint32(&st->buffer,st->setup_session_id);

    st->retries=1; /* Peer will retransmit MSG5 if necessary */
    return True;
}

static bool_t process_msg6(struct site *st, struct buffer_if *msg6,
			   struct sockaddr_in *src)
{
    struct msg0 m;
    string_t transform_err;

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
    CHECK_EMPTY(msg6);
    return True;
}

static bool_t process_msg0(struct site *st, struct buffer_if *msg0,
			   struct sockaddr_in *src)
{
    struct msg0 m;
    string_t transform_err;
    uint32_t type;

    if (!st->current_valid) {
	slog(st,LOG_DROP,"incoming message but no current key -> dropping");
	if (st->state==SITE_RUN) {
	    slog(st,LOG_SETUP_INIT|LOG_STATE,
		 "now initiating setup of new key");
	    return enter_state_resolve(st);
	}
	return False;
    }

    if (!unpick_msg0(st,msg0,&m)) return False;

    if (st->current_transform->reverse(st->current_transform->st,
				       msg0,&transform_err)) {
	/* There's a problem */
	slog(st,LOG_SEC,"transform: %s",transform_err);
	return False;
    }
    CHECK_AVAIL(msg0,4);
    type=buf_unprepend_uint32(msg0);
    switch(type) {
    case LABEL_MSG9:
	/* Deliver to netlink layer */
	st->netlink->deliver(st->netlink->st,st->netlink_cid,msg0);
	return True;
	break;
    default:
	slog(st,LOG_SEC,"incoming message of type %08x (unknown)",type);
	break;
    }
    return False;
}

static void dump_packet(struct site *st, struct buffer_if *buf,
			struct sockaddr_in *addr, bool_t incoming)
{
    uint32_t dest=ntohl(*(uint32_t *)buf->start);
    uint32_t source=ntohl(*(uint32_t *)(buf->start+4));
    uint32_t msgtype=ntohl(*(uint32_t *)(buf->start+8));

    if (st->log_events & LOG_DUMP)
	log(st->log,0,"(%s,%s): %s: %08x<-%08x: %08x:",
	    st->localname,st->remotename,incoming?"incoming":"outgoing",
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
	st->timeout=st->now+st->setup_timeout;
	st->retries--;
	return True;
    } else {
	slog(st,LOG_SETUP_TIMEOUT,"timed out sending key setup packet");
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
	st->setup_peer.sin_family=AF_INET;
	st->setup_peer.sin_port=htons(st->remoteport);
	st->setup_peer.sin_addr=*address;
	enter_state_sentmsg1(st);
    } else {
	/* Resolution failed */
	slog(st,LOG_ERROR,"resolution of %s failed",st->address);
	enter_state_run(st);
    }
}

static void activate_new_key(struct site *st)
{
    struct transform_inst_if *t;

    t=st->current_transform;
    st->current_transform=st->new_transform;
    st->new_transform=t;

    t->delkey(t->st);
    st->state=SITE_RUN;
    st->timeout=0;
    st->current_valid=True;
    st->current_key_timeout=st->now+st->key_lifetime;
    st->peer=st->setup_peer;
    st->peer_valid=True;
    st->remote_session_id=st->setup_session_id;

    slog(st,LOG_ACTIVATE_KEY,"new key activated");
}

static void state_assert(struct site *st, bool_t ok)
{
    if (!ok) fatal("state_assert\n");
}

static void enter_state_stop(struct site *st)
{
    st->state=SITE_STOP;
    st->timeout=0;
    st->current_transform->delkey(st->current_transform->st);
    st->current_valid=False;
    st->current_key_timeout=0;
    
    st->peer_valid=False;
    
    st->new_transform->delkey(st->new_transform->st);
}

static void enter_state_run(struct site *st)
{
    slog(st,LOG_STATE,"entering state RUN");
    st->state=SITE_RUN;
    st->timeout=0;
    st->netlink->set_delivery(st->netlink->st,st->netlink_cid,True);
    /* XXX get rid of key setup data */
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

static bool_t enter_state_sentmsg1(struct site *st)
{
    state_assert(st,st->state==SITE_RUN || st->state==SITE_RESOLVE);
    slog(st,LOG_STATE,"entering state SENTMSG1");
    if (generate_msg1(st) && send_msg(st)) {
	st->state=SITE_SENTMSG1;
	return True;
    }
    slog(st,LOG_ERROR,"error entering state SENTMSG1");
    st->buffer.free=False; /* Can't tell which it was, but enter_state_wait()
			      will do a BUF_FREE() */
    enter_state_wait(st);
    return False;
}

static bool_t enter_state_sentmsg2(struct site *st)
{
    state_assert(st,st->state==SITE_RUN || st->state==SITE_RESOLVE ||
		 st->state==SITE_SENTMSG1 || st->state==SITE_WAIT);
    slog(st,LOG_STATE,"entering state SENTMSG2");
    if (generate_msg2(st) && send_msg(st)) {
	st->state=SITE_SENTMSG2;
	return True;
    }
    slog(st,LOG_ERROR,"error entering state SENTMSG2");
    st->buffer.free=False;
    enter_state_wait(st);
    return False;
}

static bool_t enter_state_sentmsg3(struct site *st)
{
    state_assert(st,st->state==SITE_SENTMSG1);
    slog(st,LOG_STATE,"entering state SENTMSG3");
    BUF_FREE(&st->buffer); /* Free message 1 */
    if (generate_msg3(st) && send_msg(st)) {
	st->state=SITE_SENTMSG3;
	return True;
    }
    slog(st,LOG_ERROR,"error entering state SENTMSG3");
    st->buffer.free=False;
    enter_state_wait(st);
    return False;
}

static bool_t enter_state_sentmsg4(struct site *st)
{
    state_assert(st,st->state==SITE_SENTMSG2);
    slog(st,LOG_STATE,"entering state SENTMSG4");
    BUF_FREE(&st->buffer); /* Free message 2 */
    if (generate_msg4(st) && send_msg(st)) {
	st->state=SITE_SENTMSG4;
	return True;
    }
    slog(st,LOG_ERROR,"error entering state SENTMSG4");
    st->buffer.free=False;
    enter_state_wait(st);
    return False;
}

static bool_t enter_state_sentmsg5(struct site *st)
{
    state_assert(st,st->state==SITE_SENTMSG3);
    slog(st,LOG_STATE,"entering state SENTMSG5");
    BUF_FREE(&st->buffer); /* Free message 3 */

    if (generate_msg5(st) && send_msg(st)) {
	st->state=SITE_SENTMSG5;
	return True;
    }
    slog(st,LOG_ERROR,"error entering state SENTMSG5");
    st->buffer.free=False;
    enter_state_wait(st);
    
    return False;
}

static bool_t send_msg6(struct site *st)
{
    state_assert(st,st->state==SITE_SENTMSG4);
    slog(st,LOG_STATE,"entering state RUN after sending msg6");
    BUF_FREE(&st->buffer); /* Free message 4 */
    if (generate_msg6(st) && send_msg(st)) {
	BUF_FREE(&st->buffer); /* Never reused */
	st->timeout=0; /* Never retransmit */
	activate_new_key(st);
	return True;
    }
    slog(st,LOG_ERROR,"error entering state RUN after sending msg6");
    st->buffer.free=False;
    enter_state_wait(st);
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
    st->peer_valid=False;
    st->netlink->set_delivery(st->netlink->st,st->netlink_cid,False);
    BUF_FREE(&st->buffer); /* will have had an outgoing packet in it */
    /* XXX Erase keys etc. */
}

static int site_beforepoll(void *sst, struct pollfd *fds, int *nfds_io,
			   int *timeout_io, const struct timeval *tv_now,
			   uint64_t *now)
{
    struct site *st=sst;

    *nfds_io=0; /* We don't use any file descriptors */
    st->now=*now;

    /* Work out when our next timeout is. The earlier of 'timeout' or
       'current_key_timeout'. A stored value of '0' indicates no timeout
       active. */
    if (st->timeout && st->timeout-*now < *timeout_io) {
	*timeout_io=st->timeout-*now;
    }

    if (st->current_key_timeout && st->current_key_timeout-*now < *timeout_io)
	*timeout_io=st->current_key_timeout-*now;

    return 0; /* success */
}

/* NB site_afterpoll will be called before site_beforepoll is ever called */
static void site_afterpoll(void *sst, struct pollfd *fds, int nfds,
			   const struct timeval *tv_now, uint64_t *now)
{
    struct site *st=sst;

    st->now=*now;
    if (st->timeout && *now>st->timeout) {
	/* Do stuff */
	st->timeout=0;
	if (st->state>=SITE_SENTMSG1 && st->state<=SITE_SENTMSG5)
	    send_msg(st);
	else if (st->state==SITE_WAIT) {
	    enter_state_run(st);
	} else {
	    slog(st,LOG_ERROR,"site_afterpoll: unexpected timeout, state=%d",
		 st->state);
	}
    }
    if (st->current_key_timeout && *now>st->current_key_timeout) {
	slog(st,LOG_TIMEOUT_KEY,"maximum key life exceeded; session closed");
	st->current_valid=False;
	st->current_transform->delkey(st->current_transform->st);
	st->current_key_timeout=0;
    }
}

/* This function is called by the netlink device to deliver packets
   intended for the remote network. The packet is in "raw" wire
   format, but is guaranteed to be word-aligned. */
static void site_outgoing(void *sst, void *cid, struct buffer_if *buf)
{
    struct site *st=sst;
    string_t transform_err;
    
    if (st->state==SITE_STOP) {
	BUF_FREE(buf);
	return;
    }

    /* In all other states we consider delivering the packet if we have
       a valid key and a valid address to send it to. */
    if (st->current_valid && st->peer_valid) {
	/* Transform it and send it */
	buf_prepend_uint32(buf,LABEL_MSG9);
	st->current_transform->forwards(st->current_transform->st,
					buf, &transform_err);
	buf_prepend_uint32(buf,LABEL_MSG0);
	buf_prepend_uint32(buf,(uint32_t)st);
	buf_prepend_uint32(buf,st->remote_session_id);
	st->comm->sendmsg(st->comm->st,buf,&st->peer);
	BUF_FREE(buf);
	return;
    }

    if (st->state==SITE_RUN) {
	BUF_FREE(buf); /* We throw the outgoing packet away */
	slog(st,LOG_SETUP_INIT,"initiating key exchange");
	enter_state_resolve(st);
	return;
    }

    /* Otherwise we're in the middle of key setup or a wait - just
       throw the outgoing packet away */
    slog(st,LOG_DROP,"discarding outgoing packet");
    BUF_FREE(buf);
    return;
}

/* This function is called by the communication device to deliver
   packets from our peers. */
static bool_t site_incoming(void *sst, struct buffer_if *buf,
			    struct sockaddr_in *source)
{
    struct site *st=sst;
    uint32_t dest=ntohl(*(uint32_t *)buf->start);

    if (dest==0) {
	if (buf->size<(st->setupsiglen+8+NONCELEN)) return False;
	/* It could be for any site - it should have LABEL_MSG1 and
	   might have our name and our peer's name in it */
	if (memcmp(buf->start+8,st->setupsig,st->setupsiglen)==0) {
	    dump_packet(st,buf,source,True);
	    /* It's addressed to us. Decide what to do about it. */
	    if (st->state==SITE_RUN || st->state==SITE_RESOLVE ||
		st->state==SITE_WAIT) {
		/* We should definitely process it */
		if (process_msg1(st,buf,source)) {
		    slog(st,LOG_SETUP_INIT,"key setup initiated by peer");
		    enter_state_sentmsg2(st);
		} else {
		    slog(st,LOG_ERROR,"failed to process incoming msg1");
		}
		BUF_FREE(buf);
		return True;
	    }
	    if (st->state==SITE_SENTMSG1) {
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
			enter_state_sentmsg2(st);
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
    if (dest==(uint32_t)st) {
	uint32_t msgtype=ntohl(*(uint32_t *)(buf->start+8));
	/* Explicitly addressed to us */
	if (msgtype!=LABEL_MSG0) dump_packet(st,buf,source,True);
	switch (msgtype) {
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
		enter_state_sentmsg3(st);
	    else {
		slog(st,LOG_SEC,"invalid MSG2");
	    }
	    break;
	case LABEL_MSG3:
	    /* Setup packet: expected only in state SENTMSG2 */
	    if (st->state!=SITE_SENTMSG2) {
		slog(st,LOG_UNEXPECTED,"unexpected MSG3");
	    } else if (process_msg3(st,buf,source))
		enter_state_sentmsg4(st);
	    else {
		slog(st,LOG_SEC,"invalid MSG3");
	    }
	    break;
	case LABEL_MSG4:
	    /* Setup packet: expected only in state SENTMSG3 */
	    if (st->state!=SITE_SENTMSG3) {
		slog(st,LOG_UNEXPECTED,"unexpected MSG4");
	    } else if (process_msg4(st,buf,source))
		enter_state_sentmsg5(st);
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
	       new_transform will now be null. XXX) */
	    if (st->state!=SITE_SENTMSG4) {
		slog(st,LOG_UNEXPECTED,"unexpected MSG5");
	    } else if (process_msg5(st,buf,source)) {
		send_msg6(st);
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
	case LABEL_MSG8:
	    /* NAK packet: enter state where we ping and check for response */
	    slog(st,LOG_ERROR,"received a NAK");
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

static list_t *site_apply(closure_t *self, struct cloc loc, dict_t *context,
			  list_t *args)
{
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
	Message(M_INFO,"site %s: talking to ourselves!\n",st->localname);
	free(st);
	return NULL;
    }
    st->netlink=find_cl_if(dict,"netlink",CL_NETLINK,True,"site",loc);
    st->comm=find_cl_if(dict,"comm",CL_COMM,True,"site",loc);
    st->resolver=find_cl_if(dict,"resolver",CL_RESOLVER,True,"site",loc);
    st->log=find_cl_if(dict,"log",CL_LOG,True,"site",loc);
    st->random=find_cl_if(dict,"random",CL_RANDOMSRC,True,"site",loc);

    st->privkey=find_cl_if(dict,"local-key",CL_RSAPRIVKEY,True,"site",loc);
    st->remoteport=dict_read_number(dict,"port",True,"site",loc,0);

    st->address=dict_read_string(dict, "address", False, "site", loc);
    dict_read_subnet_list(dict, "networks", True, "site", loc,
			  &st->remotenets);
    st->pubkey=find_cl_if(dict,"key",CL_RSAPUBKEY,True,"site",loc);

    st->transform=
	find_cl_if(dict,"transform",CL_TRANSFORM,True,"site",loc);

    st->dh=find_cl_if(dict,"dh",CL_DH,True,"site",loc);
    st->hash=find_cl_if(dict,"hash",CL_HASH,True,"site",loc);

    st->key_lifetime=dict_read_number(dict,"key-lifetime",
				      False,"site",loc,DEFAULT_KEY_LIFETIME);
    st->setup_retries=dict_read_number(dict,"setup-retries",
				       False,"site",loc,DEFAULT_SETUP_RETRIES);
    st->setup_timeout=dict_read_number(dict,"setup-timeout",
				       False,"site",loc,DEFAULT_SETUP_TIMEOUT);
    st->wait_timeout=dict_read_number(dict,"wait-time",
				      False,"site",loc,DEFAULT_WAIT_TIME);
    /* XXX should be configurable */
    st->log_events=LOG_SEC|LOG_ERROR|
	LOG_ACTIVATE_KEY|LOG_TIMEOUT_KEY|LOG_SETUP_INIT|LOG_SETUP_TIMEOUT;

    st->tunname=safe_malloc(strlen(st->localname)+strlen(st->remotename)+5,
			    "site_apply");
    sprintf(st->tunname,"%s<->%s",st->localname,st->remotename);

    /* The information we expect to see in incoming messages of type 1 */
    /* XXX fix this bit for unaligned access */
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
    st->netlink_cid=st->netlink->regnets(st->netlink->st, &st->remotenets,
					 site_outgoing, st,
					 st->transform->max_start_pad+(4*4),
					 st->transform->max_end_pad,
					 st->tunname);

    st->comm->request_notify(st->comm->st, st, site_incoming);

    st->current_transform=st->transform->create(st->transform->st);
    st->new_transform=st->transform->create(st->transform->st);

    enter_state_stop(st);

    return new_closure(&st->cl);
}

init_module site_module;
void site_module(dict_t *dict)
{
    add_closure(dict,"site",site_apply);
}
