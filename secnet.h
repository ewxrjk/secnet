/* Core interface of secnet, to be used by all modules */
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

#ifndef secnet_h
#define secnet_h

#define ADNS_FEATURE_MANYAF

#include "config.h"
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <fnmatch.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <bsd/sys/queue.h>

#include "osdep.h"

#define MAX_PEER_ADDRS 5
/* send at most this many copies; honour at most that many addresses */

#define MAX_NAK_MSG 80
#define MAX_SIG_KEYS 4

struct hash_if;
struct comm_if;
struct comm_addr;
struct priomsg;
struct log_if;
struct buffer_if;
struct sigpubkey_if;
struct sigprivkey_if;

typedef char *string_t;
typedef const char *cstring_t;

#define False (_Bool)0
#define True  (_Bool)1
typedef _Bool bool_t;

union iaddr {
    struct sockaddr sa;
    struct sockaddr_in sin;
#ifdef CONFIG_IPV6
    struct sockaddr_in6 sin6;
#endif
};

#define GRPIDSZ 4
#define ALGIDSZ 1
#define KEYIDSZ (GRPIDSZ+ALGIDSZ)
  /* Changing these is complex: this is the group id plus algo id */
  /* They are costructed by pubkeys.fl.pl.  Also hardcoded in _PR_ */
struct sigkeyid { uint8_t b[KEYIDSZ]; };

#define SIGKEYID_PR_FMT "%02x%02x%02x%02x%02x"
#define SIGKEYID_PR_VAL(id) /* SIGKEYID_PR_VAL(const sigkeyid *id) */	\
    ((id) == (const struct sigkeyid*)0, (id)->b[0]),			\
    (id)->b[1],(id)->b[2],(id)->b[3],(id)->b[4]
static inline bool_t sigkeyid_equal(const struct sigkeyid *a,
				    const struct sigkeyid *b) {
    return !memcmp(a->b, b->b, KEYIDSZ);
}

#define SERIALSZ 4
typedef uint32_t serialt;
static inline int serial_cmp(serialt a, serialt b) {
    if (a==b) return 0;
    if (!a) return -1;
    if (!b) return +1;
    return b-a <= (serialt)0x7fffffffUL ? +1 : -1;
}

#define ASSERT(x) do { if (!(x)) { fatal("assertion failed line %d file " \
					 __FILE__,__LINE__); } } while(0)

/* from version.c */

extern char version[];

/* from logmsg.c */
extern uint32_t message_level;
extern bool_t secnet_is_daemon;
extern struct log_if *system_log;

/* from process.c */
extern void start_signal_handling(void);

void afterfork(void);
/* Must be called before exec in every child made after
   start_signal_handling.  Safe to call in earlier children too. */

void childpersist_closefd_hook(void *fd_p, uint32_t newphase);
/* Convenience hook function for use with add_hook PHASE_CHILDPERSIST.
   With `int fd' in your state struct, pass fd_p=&fd.  The hook checks
   whether fd>=0, so you can use it for an fd which is only sometimes
   open.  This function will set fd to -1, so it is idempotent. */

/***** CONFIGURATION support *****/

extern bool_t just_check_config; /* If True then we're going to exit after
				    reading the configuration file */
extern bool_t background; /* If True then we'll eventually run as a daemon */

typedef struct dict dict_t;        /* Configuration dictionary */
typedef struct closure closure_t;
typedef struct item item_t;
typedef struct list list_t;        /* A list of items */

/* Configuration file location, for error-reporting */
struct cloc {
    cstring_t file;
    int line;
};

/* Modules export closures, which can be invoked from the configuration file.
   "Invoking" a closure usually returns another closure (of a different
   type), but can actually return any configuration object. */
typedef list_t *(apply_fn)(closure_t *self, struct cloc loc,
			   dict_t *context, list_t *data);
struct closure {
    cstring_t description; /* For debugging */
    uint32_t type; /* Central registry... */
    apply_fn *apply;
    void *interface; /* Interface for use inside secnet; depends on type */
};

enum types { t_null, t_bool, t_string, t_number, t_dict, t_closure };
struct item {
    enum types type;
    union {
	bool_t bool;
	string_t string;
	uint32_t number;
	dict_t *dict;
	closure_t *closure;
    } data;
    struct cloc loc;
};

/* Note that it is unwise to use this structure directly; use the list
   manipulation functions instead. */
struct list {
    item_t *item;
    struct list *next;
};

/* In the following two lookup functions, NULL means 'not found' */
/* Lookup a value in the specified dictionary, or its parents */
extern list_t *dict_lookup(dict_t *dict, cstring_t key);
/* Lookup a value in just the specified dictionary */
extern list_t *dict_lookup_primitive(dict_t *dict, cstring_t key);
/* Add a value to the specified dictionary */
extern void dict_add(dict_t *dict, cstring_t key, list_t *val);
/* Obtain an array of keys in the dictionary. malloced; caller frees */
extern cstring_t *dict_keys(dict_t *dict);

/* List-manipulation functions */
extern list_t *list_new(void);
extern int32_t list_length(const list_t *a);
extern list_t *list_append(list_t *a, item_t *i);
extern list_t *list_append_list(list_t *a, list_t *b);
/* Returns an item from the list (index starts at 0), or NULL */
extern item_t *list_elem(list_t *l, int32_t index);

/* Convenience functions */
extern list_t *new_closure(closure_t *cl);
extern void add_closure(dict_t *dict, cstring_t name, apply_fn apply);
extern void *find_cl_if(dict_t *dict, cstring_t name, uint32_t type,
			bool_t fail_if_invalid, cstring_t desc,
			struct cloc loc);
extern item_t *dict_find_item(dict_t *dict, cstring_t key, bool_t required,
			      cstring_t desc, struct cloc loc);
extern string_t dict_read_string(dict_t *dict, cstring_t key, bool_t required,
				 cstring_t desc, struct cloc loc);
extern uint32_t dict_read_number(dict_t *dict, cstring_t key, bool_t required,
				 cstring_t desc, struct cloc loc,
				 uint32_t def);
  /* return value can safely be assigned to int32_t */
extern bool_t dict_read_bool(dict_t *dict, cstring_t key, bool_t required,
			     cstring_t desc, struct cloc loc, bool_t def);
extern dict_t *dict_read_dict(dict_t *dict, cstring_t key, bool_t required,
			cstring_t desc, struct cloc loc);
const char **dict_read_string_array(dict_t *dict, cstring_t key,
				    bool_t required, cstring_t desc,
				    struct cloc loc, const char *const *def);
  /* Return value is a NULL-terminated array obtained from malloc;
   * Individual string values are still owned by config file machinery
   * and must not be modified or freed.  Returns NULL if key not
   * found. */

struct flagstr {
    cstring_t name;
    uint32_t value;
};
extern uint32_t string_to_word(cstring_t s, struct cloc loc,
			       struct flagstr *f, cstring_t desc);
extern uint32_t string_list_to_word(list_t *l, struct flagstr *f,
				    cstring_t desc);

/***** END of configuration support *****/

/***** UTILITY functions *****/

extern char *safe_strdup(const char *string, const char *message);
extern void *safe_malloc(size_t size, const char *message);
extern void *safe_malloc_ary(size_t size, size_t count, const char *message);
extern void *safe_realloc_ary(void *p, size_t size, size_t count,
			      const char *message);

#define NEW(p)					\
    ((p)=safe_malloc(sizeof(*(p)),		\
		     __FILE__ ":" #p))
#define NEW_ARY(p,count)					\
    ((p)=safe_malloc_ary(sizeof(*(p)),(count),			\
			 __FILE__ ":" #p "[" #count "]"))
#define REALLOC_ARY(p,count)					\
    ((p)=safe_realloc_ary((p),sizeof(*(p)),(count),		\
			  __FILE__ ":" #p "[" #count "]"))

void setcloexec(int fd); /* cannot fail */
void setnonblock(int fd); /* cannot fail */
void pipe_cloexec(int fd[2]); /* pipe(), setcloexec() twice; cannot fail */

extern int sys_cmd(const char *file, const char *argc, ...);

extern uint64_t now_global;
extern struct timeval tv_now_global;

static const uint64_t       *const now    = &now_global;
static const struct timeval *const tv_now = &tv_now_global;

/* "now" is current program time, in milliseconds. It is derived
   from tv_now. Both are provided by the event loop. */

/***** END of utility functions *****/

/***** START of max_start_pad handling *****/

extern int32_t site_max_start_pad, transform_max_start_pad,
    comm_max_start_pad;

void update_max_start_pad(int32_t *our_module_global, int32_t our_instance);
int32_t calculate_max_start_pad(void);

/***** END of max_start_pad handling *****/

/***** SCHEDULING support */

/* If nfds_io is insufficient for your needs, set it to the required
   number and return ERANGE. timeout is in milliseconds; if it is too
   high then lower it. It starts at -1 (==infinite). */
/* Note that beforepoll_fn may NOT do anything which might change the
   fds or timeouts wanted by other registered poll loop loopers.
   Callers should make sure of this by not making any calls into other
   modules from the beforepoll_fn; the easiest way to ensure this is
   for beforepoll_fn to only retreive information and not take any
   action.
 */
typedef int beforepoll_fn(void *st, struct pollfd *fds, int *nfds_io,
			  int *timeout_io);
typedef void afterpoll_fn(void *st, struct pollfd *fds, int nfds);
  /* If beforepoll_fn returned ERANGE, afterpoll_fn gets nfds==0.
     afterpoll_fn never gets !!(fds[].revents & POLLNVAL) - such
     a report is detected as a fatal error by the event loop. */

/* void BEFOREPOLL_WANT_FDS(int want);
 *   Expects: int *nfds_io;
 *   Can perform non-local exit.
 * Checks whether there is space for want fds.  If so, sets *nfds_io.
 * If not, sets *nfds_io and returns. */
#define BEFOREPOLL_WANT_FDS(want) do{				\
    if (*nfds_io<(want)) { *nfds_io=(want); return ERANGE; }	\
    *nfds_io=(want);						\
  }while(0)

/* Register interest in the main loop of the program. Before a call
   to poll() your supplied beforepoll function will be called. After
   the call to poll() the supplied afterpoll function will be called. */
struct poll_interest *register_for_poll(void *st, beforepoll_fn *before,
			      afterpoll_fn *after, cstring_t desc);
void deregister_for_poll(struct poll_interest *i);

/***** END of scheduling support */

/***** PROGRAM LIFETIME support */

/* The secnet program goes through a number of phases in its lifetime.
   Module code may arrange to be called just as various phases are
   entered.
 
   Remember to update the table in util.c if changing the set of
   phases. */

enum phase {
    PHASE_INIT,
    PHASE_GETOPTS,             /* Process command-line arguments */
    PHASE_READCONFIG,          /* Parse and process configuration file */
    PHASE_SETUP,               /* Process information in configuration */
    PHASE_DAEMONIZE,           /* Become a daemon (if necessary) */
    PHASE_GETRESOURCES,        /* Obtain all external resources */
    PHASE_DROPPRIV,            /* Last chance for privileged operations */
    PHASE_RUN,
    PHASE_SHUTDOWN,            /* About to die; delete key material, etc. */
    PHASE_CHILDPERSIST,        /* Forked long-term child: close fds, etc. */
    /* Keep this last: */
    NR_PHASES,
};

/* Each module should, in its CHILDPERSIST hooks, close all fds which
   constitute ownership of important operating system resources, or
   which are used for IPC with other processes who want to get the
   usual disconnection effects if the main secnet process dies.
   CHILDPERSIST hooks are not run if the child is going to exec;
   so fds such as described above should be CLOEXEC too. */

typedef void hook_fn(void *self, uint32_t newphase);
bool_t add_hook(uint32_t phase, hook_fn *f, void *state);
bool_t remove_hook(uint32_t phase, hook_fn *f, void *state);

extern uint32_t current_phase;
extern void enter_phase(uint32_t new_phase);

void phase_hooks_init(void); /* for main() only */
void clear_phase_hooks(uint32_t phase); /* for afterfork() */

/* Some features (like netlink 'soft' routes) require that secnet
   retain root privileges.  They should indicate that here when
   appropriate. */
extern bool_t require_root_privileges;
extern cstring_t require_root_privileges_explanation;

/* Some modules may want to know whether secnet is going to drop
   privilege, so that they know whether to do privsep.  Call only
   in phases SETUP and later. */
bool_t will_droppriv(void);

/***** END of program lifetime support *****/

/***** MODULE support *****/

/* Module initialisation function type - modules export one function of
   this type which is called to initialise them. For dynamically loaded
   modules it's called "secnet_module". */
typedef void init_module(dict_t *dict);

extern void init_builtin_modules(dict_t *dict);

extern init_module pubkeys_init;
extern init_module resolver_module;
extern init_module random_module;
extern init_module udp_module;
extern init_module polypath_module;
extern init_module util_module;
extern init_module site_module;
extern init_module transform_eax_module;
extern init_module transform_cbcmac_module;
extern init_module netlink_module;
extern init_module rsa_module;
extern init_module dh_module;
extern init_module md5_module;
extern init_module slip_module;
extern init_module tun_module;
extern init_module sha1_module;
extern init_module log_module;
extern init_module privcache_module;

/***** END of module support *****/

/***** SIGNATURE SCHEMES *****/

struct sigscheme_info;

typedef bool_t sigscheme_loadpub(const struct sigscheme_info *algo,
				 struct buffer_if *pubkeydata,
				 struct sigpubkey_if **sigpub_r,
				 closure_t **closure_r,
				 struct log_if *log, struct cloc loc);
  /* pubkeydata is (supposedly) for this algorithm.
   * loadpub should log an error if it fails.
   * pubkeydata may be modified (but not freed).
   * both *sigpub_r and *closure_r must always be written and must
   * refer to the same object, so on successful return
   * (*closure_r)->type==CL_SIGPUBKEY
   * and (*closure_r)->interface==*sigpub_r */

typedef bool_t sigscheme_loadpriv(const struct sigscheme_info *algo,
				  struct buffer_if *privkeydata,
				  struct sigprivkey_if **sigpriv_r,
				  closure_t **closure_r,
				  struct log_if *log, struct cloc loc);
  /* Ideally, check whether privkeydata contains data for any algorithm.
   * That avoids security problems if a key file is misidentified (which
   * might happen if the file is simply renamed).
   * If there is an error (including that the key data is not for this
   * algorithm, return False and log an error at M_ERROR.
   * On entry privkeydata->base==start.  loadpriv may modify
   * privkeydata, including the contents. */

struct sigscheme_info {
    const char *name;
    const uint8_t algid;
    sigscheme_loadpub *loadpub;
    sigscheme_loadpriv *loadpriv;
};

extern const struct sigscheme_info rsa1_sigscheme;
extern const struct sigscheme_info sigschemes[]; /* sentinel has name==0 */

const struct sigscheme_info *sigscheme_lookup(const char *name);

extern sigscheme_loadpriv rsa1_loadpriv;
extern sigscheme_loadpub  rsa1_loadpub;

/***** END of signature schemes *****/

/***** CLOSURE TYPES and interface definitions *****/

#define CL_PURE         0
#define CL_RESOLVER     1
#define CL_RANDOMSRC    2
#define CL_SIGPUBKEY    3
#define CL_SIGPRIVKEY   4
#define CL_COMM         5
#define CL_IPIF         6
#define CL_LOG          7
#define CL_SITE         8
#define CL_TRANSFORM    9
#define CL_DH          11
#define CL_HASH        12
#define CL_BUFFER      13
#define CL_NETLINK     14
#define CL_PRIVCACHE   15

struct buffer_if;

struct alg_msg_data {
    uint8_t *start;
    int32_t len;
};

/* PURE closure requires no interface */

/* RESOLVER interface */

/* Answers to queries are delivered to a function of this
   type. 'address' will be NULL if there was a problem with the query. It
   will be freed once resolve_answer_fn returns.  naddrs is the actual
   size of the array at addrs; was_naddrs is the number of addresses
   actually found in the DNS, which may be bigger if addrs is equal
   to MAX_PEER_ADDRS (ie there were too many). */
typedef void resolve_answer_fn(void *st, const struct comm_addr *addrs,
			       int naddrs, int was_naddrs,
			       const char *name, const char *failwhy);
  /* name is the same ptr as passed to request, so its lifetime must
   * be suitable*/
typedef bool_t resolve_request_fn(void *st, cstring_t name,
				  int remoteport, struct comm_if *comm,
				  resolve_answer_fn *cb, void *cst);
struct resolver_if {
    void *st;
    resolve_request_fn *request;
};

/* RANDOMSRC interface */

/* Return some random data. Cannot fail. */
typedef void random_fn(void *st, int32_t bytes, uint8_t *buff);

struct random_if {
    void *st;
    bool_t blocking;
    random_fn *generate;
};

/* SIGPUBKEY interface */

typedef void sig_sethash_fn(void *st, struct hash_if *hash);
typedef void sig_dispose_fn(void *st);

typedef bool_t sig_unpick_fn(void *sst, struct buffer_if *msg,
			     struct alg_msg_data *sig);
typedef bool_t sig_checksig_fn(void *st, uint8_t *data, int32_t datalen,
			       const struct alg_msg_data *sig);
struct sigpubkey_if {
    void *st;
    sig_sethash_fn *sethash; /* must be called before use, if non-0 */
    sig_unpick_fn *unpick;
    sig_checksig_fn *check;
    const struct hash_if *hash;
    sig_dispose_fn *dispose;
};

/* SIGPRIVKEY interface */

/* Appends the signature to msg.
 * Can fail and returnn False, eg if the buffer is too small. */
typedef bool_t sig_makesig_fn(void *st, uint8_t *data, int32_t datalen,
			      struct buffer_if *msg);
struct sigprivkey_if {
    void *st;
    sig_sethash_fn *sethash; /* must be called before use, if non-0 */
    sig_makesig_fn *sign;
    const struct hash_if *hash;
    sig_dispose_fn *dispose;
};

/* PRIVCACHE interface */

typedef struct sigprivkey_if *privcache_lookup_fn(void *st,
					   const struct sigkeyid *id,
					   struct log_if*);
  /* Return is valid only until you return from the current event!
   * You do not need to call ->sethash. */

struct privcache_if {
    void *st;
    privcache_lookup_fn *lookup;
};

/* COMM interface */

struct comm_addr {
    /* This struct is pure data; in particular comm's clients may
       freely copy it. */
    struct comm_if *comm;
    union iaddr ia;
    int ix; /* see comment `Re comm_addr.ix' in udp.c */
};

struct comm_clientinfo; /* private for comm */

typedef struct comm_clientinfo *comm_clientinfo_fn(void *state, dict_t*,
						   struct cloc cloc);
/* A comm client may call this during configuration, and then pass
 * the resulting comm_clientinfo* to some or all sendmsg calls.
 * The semantics depend on the dict and defined by the comm, and
 * should be documented in README. */

enum {
    comm_notify_whynot_general,
    comm_notify_whynot_unpick,
    comm_notify_whynot_name_local,
    comm_notify_whynot_name_remote,
};

/* Return True if the packet was processed, and shouldn't be passed to
   any other potential receivers. (buf is freed iff True returned.) */
typedef bool_t comm_notify_fn(void *state, struct buffer_if *buf,
			      const struct comm_addr *source,
			      struct priomsg *whynot);
typedef void comm_request_notify_fn(void *commst, void *nst,
				    comm_notify_fn *fn);
typedef void comm_release_notify_fn(void *commst, void *nst,
				    comm_notify_fn *fn);
typedef bool_t comm_sendmsg_fn(void *commst, struct buffer_if *buf,
			       const struct comm_addr *dest,
			       struct comm_clientinfo* /* 0 OK */);
  /* Only returns false if (we know that) the local network
   * environment is such that this address cannot work; transient
   * or unknown/unexpected failures return true. */
typedef const char *comm_addr_to_string_fn(void *commst,
					   const struct comm_addr *ca);
        /* Returned string is in a static buffer. */
struct comm_if {
    void *st;
    comm_clientinfo_fn *clientinfo;
    comm_request_notify_fn *request_notify;
    comm_release_notify_fn *release_notify;
    comm_sendmsg_fn *sendmsg;
    comm_addr_to_string_fn *addr_to_string;
};

bool_t iaddr_equal(const union iaddr *ia, const union iaddr *ib,
		   bool_t ignoreport);

static inline const char *comm_addr_to_string(const struct comm_addr *ca)
{
    return ca->comm->addr_to_string(ca->comm->st, ca);
}

static inline bool_t comm_addr_equal(const struct comm_addr *a,
				     const struct comm_addr *b)
{
    return a->comm==b->comm && iaddr_equal(&a->ia,&b->ia,False);
}

/* LOG interface */

#define LOG_MESSAGE_BUFLEN 1023

typedef void log_msg_fn(void *st, int class, const char *message, ...);
typedef void log_vmsg_fn(void *st, int class, const char *message,
			 va_list args);
struct log_if {
    void *st;
    log_vmsg_fn *vlogfn; /* printf format checking.  Use [v]slilog instead */
    char buff[LOG_MESSAGE_BUFLEN+1];
};
/* (convenience functions, defined in util.c) */
extern void slilog(struct log_if *lf, int class, const char *message, ...)
FORMAT(printf,3,4);
extern void vslilog(struct log_if *lf, int class, const char *message, va_list)
FORMAT(printf,3,0);

/* Versions which take (parts of) (multiple) messages, using \n to
 * distinguish one message from another. */
extern void slilog_part(struct log_if *lf, int class, const char *message, ...)
FORMAT(printf,3,4);
extern void vslilog_part(struct log_if *lf, int class, const char *message,
			 va_list) FORMAT(printf,3,0);

void cfgfile_log__vmsg(void *sst, int class, const char *message, va_list);
struct cfgfile_log {
    struct log_if log;
    /* private fields */
    struct cloc loc;
    const char *facility;
};
static inline void cfgfile_log_init(struct cfgfile_log *cfl,
				    struct cloc loc, const char *facility)
{
    cfl->log.st=cfl;
    cfl->log.vlogfn=cfgfile_log__vmsg;
    cfl->loc=loc;
    cfl->facility=facility;
}

/* SITE interface */

/* Pretty much a placeholder; allows starting and stopping of processing,
   key expiry, etc. */
typedef void site_control_fn(void *st, bool_t run);
typedef uint32_t site_status_fn(void *st);
struct site_if {
    void *st;
    site_control_fn *control;
    site_status_fn *status;
};

/* TRANSFORM interface */

/* A reversable transformation. Transforms buffer in-place; may add
   data to start or end. (Reverse transformations decrease
   length, of course.)  Transformations may be key-dependent, in which
   case key material is passed in at initialisation time. They may
   also depend on internal factors (eg. time) and keep internal
   state. A struct transform_if only represents a particular type of
   transformation; instances of the transformation (eg. with
   particular key material) have a different C type. The same
   secret key will be used in opposite directions between a pair of
   secnets; one of these pairs will get direction==False, the other True. */

typedef struct transform_inst_if *transform_createinstance_fn(void *st);
typedef bool_t transform_setkey_fn(void *st, uint8_t *key, int32_t keylen,
				   bool_t direction);
typedef bool_t transform_valid_fn(void *st); /* 0: no key; 1: ok */
typedef void transform_delkey_fn(void *st);
typedef void transform_destroyinstance_fn(void *st);

typedef enum {
    transform_apply_ok       = 0, /* all is well (everyone may assume==0) */
    transform_apply_err      = 1, /* any other problem */
    transform_apply_seqrange = 2,
        /* message decrypted but sequence number was out of recent range */
    transform_apply_seqdupe  = 3,
        /* message decrypted but was dupe of recent packet */
} transform_apply_return;

static inline bool_t
transform_apply_return_badseq(transform_apply_return problem) {
    return problem == transform_apply_seqrange ||
	   problem == transform_apply_seqdupe;
}

typedef transform_apply_return transform_apply_fn(void *st,
        struct buffer_if *buf, const char **errmsg);

struct transform_inst_if {
    void *st;
    transform_setkey_fn *setkey;
    transform_valid_fn *valid;
    transform_delkey_fn *delkey;
    transform_apply_fn *forwards;
    transform_apply_fn *reverse;
    transform_destroyinstance_fn *destroy;
};

struct transform_if {
    void *st;
    int capab_bit;
    int32_t keylen; /* <<< INT_MAX */
    transform_createinstance_fn *create;
};

/* NETLINK interface */

/* Used by netlink to deliver to site, and by site to deliver to
   netlink.  cid is the client identifier returned by
   netlink_regnets_fn.  If buf has size 0 then the function is just
   being called for its site-effects (eg. making the site code attempt
   to bring up a network link) */
typedef void netlink_deliver_fn(void *st, struct buffer_if *buf);
/* site code can tell netlink when outgoing packets will be dropped,
   so netlink can generate appropriate ICMP and make routing decisions */
#define LINK_QUALITY_UNUSED 0   /* This link is unused, do not make this netlink */
#define LINK_QUALITY_DOWN 1   /* No chance of a packet being delivered right away*/
#define LINK_QUALITY_DOWN_STALE_ADDRESS 2 /* Link down, old address information */
#define LINK_QUALITY_DOWN_CURRENT_ADDRESS 3 /* Link down, current address information */
#define LINK_QUALITY_UP 4     /* Link active */
#define MAXIMUM_LINK_QUALITY 3
typedef void netlink_link_quality_fn(void *st, uint32_t quality);
typedef void netlink_register_fn(void *st, netlink_deliver_fn *deliver,
				 void *dst, uint32_t *localmtu_r /* NULL ok */);
typedef void netlink_output_config_fn(void *st, struct buffer_if *buf);
typedef bool_t netlink_check_config_fn(void *st, struct buffer_if *buf);
typedef void netlink_set_mtu_fn(void *st, int32_t new_mtu);
struct netlink_if {
    void *st;
    netlink_register_fn *reg;
    netlink_deliver_fn *deliver;
    netlink_link_quality_fn *set_quality;
    netlink_set_mtu_fn *set_mtu;
};

/* DH interface */

/* Returns public key as a malloced hex string */
typedef string_t dh_makepublic_fn(void *st, uint8_t *secret,
				  int32_t secretlen);
/* Fills buffer (up to buflen) with shared secret */
typedef void dh_makeshared_fn(void *st, uint8_t *secret,
			      int32_t secretlen, cstring_t rempublic,
			      uint8_t *sharedsecret, int32_t buflen);
struct dh_if {
    void *st;
    int32_t len; /* Approximate size of modulus in bytes */
    int32_t ceil_len; /* Number of bytes just sufficient to contain modulus */
    dh_makepublic_fn *makepublic;
    dh_makeshared_fn *makeshared;
};

/* HASH interface */

typedef void hash_init_fn(void *st /* slen bytes alloc'd by caller */);
typedef void hash_update_fn(void *st, const void *buf, int32_t len);
typedef void hash_final_fn(void *st, uint8_t *digest /* hlen bytes */);
struct hash_if {
    int32_t slen; /* State length in bytes */
    int32_t hlen; /* Hash output length in bytes */
    hash_init_fn *init;
    hash_update_fn *update;
    hash_final_fn *final;
};

/* BUFFER interface */

struct buffer_if {
    bool_t free;
    cstring_t owner; /* Set to constant string */
    struct cloc loc; /* Where we were defined */
    uint8_t *base;
    uint8_t *start;
    int32_t size; /* Size of buffer contents */
    int32_t alloclen; /* Total length allocated at base */
};

/***** LOG functions *****/

#define M_DEBUG_CONFIG 0x001
#define M_DEBUG_PHASE  0x002
#define M_DEBUG        0x004
#define M_INFO	       0x008
#define M_NOTICE       0x010
#define M_WARNING      0x020
#define M_ERR	       0x040
#define M_SECURITY     0x080
#define M_FATAL	       0x100

/* The fatal() family of functions require messages that do not end in '\n' */
extern NORETURN(fatal(const char *message, ...)) FORMAT(printf,1,2);
extern NORETURN(fatal_perror(const char *message, ...)) FORMAT(printf,1,2);
extern NORETURN(fatal_status(int status, const char *message, ...))
       FORMAT(printf,2,3);
extern NORETURN(fatal_perror_status(int status, const char *message, ...))
       FORMAT(printf,2,3);

/* Convenient nonfatal logging.  Requires message that does not end in '\n'.
 * If class contains M_FATAL, exits (after entering PHASE_SHUTDOWN).
 * lg, errnoval and loc may sensibly be 0.  desc must NOT be 0.
 * lg_[v]perror save and restore errno. */
void lg_vperror(struct log_if *lg, const char *desc, struct cloc *loc,
		int class, int errnoval, const char *fmt, va_list al)
    FORMAT(printf,6,0);
void lg_perror(struct log_if *lg, const char *desc, struct cloc *loc,
	       int class, int errnoval, const char *fmt, ...)
    FORMAT(printf,6,7);
void lg_exitstatus(struct log_if *lg, const char *desc, struct cloc *loc,
		   int class, int status, const char *progname);

/* The cfgfatal() family of functions require messages that end in '\n' */
extern NORETURN(cfgfatal(struct cloc loc, cstring_t facility,
			 const char *message, ...)) FORMAT(printf,3,4);
extern void cfgfile_postreadcheck(struct cloc loc, FILE *f);
extern NORETURN(vcfgfatal_maybefile(FILE *maybe_f, struct cloc loc,
				    cstring_t facility, const char *message,
				    va_list, const char *suffix))
    FORMAT(printf,4,0);
extern NORETURN(cfgfatal_maybefile(FILE *maybe_f, struct cloc loc,
				   cstring_t facility,
				   const char *message, ...))
    FORMAT(printf,4,5);

extern void Message(uint32_t class, const char *message, ...)
    FORMAT(printf,2,3);
extern void log_from_fd(int fd, cstring_t prefix, struct log_if *log);

/***** END of log functions *****/

#define STRING2(x) #x
#define STRING(x) STRING2(x)

#define FILLZERO(obj) (memset(&(obj),0,sizeof((obj))))
#define ARRAY_SIZE(ary) (sizeof((ary))/sizeof((ary)[0]))

/*
 * void COPY_OBJ(  OBJECT& dst, const OBJECT& src);
 * void COPY_ARRAY(OBJECT *dst, const OBJECT *src, INTEGER count);
 *   // Typesafe: we check that the type OBJECT is the same in both cases.
 *   // It is OK to use COPY_OBJ on an array object, provided dst is
 *   // _actually_ the whole array object and not decayed into a
 *   // pointer (e.g. a formal parameter).
 */
#define COPY_OBJ(dst,src) \
    (&(dst)==&(src), memcpy(&(dst),&(src),sizeof((dst))))
#define COPY_ARRAY(dst,src,count) \
    (&(dst)[0]==&(src)[0], memcpy((dst),(src),sizeof((dst)[0])*(count)))

#endif /* secnet_h */
