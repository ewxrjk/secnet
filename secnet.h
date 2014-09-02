/* Core interface of secnet, to be used by all modules */

#ifndef secnet_h
#define secnet_h

#include "config.h"
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_PEER_ADDRS 5
/* send at most this many copies; honour at most that many addresses */

struct comm_if;
struct comm_addr;

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

void setcloexec(int fd); /* cannot fail */
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
   high then lower it. It starts at -1 (==infinite) */
typedef int beforepoll_fn(void *st, struct pollfd *fds, int *nfds_io,
			  int *timeout_io);
typedef void afterpoll_fn(void *st, struct pollfd *fds, int nfds);

/* Register interest in the main loop of the program. Before a call
   to poll() your supplied beforepoll function will be called. After
   the call to poll() the supplied afterpoll function will be called.
   max_nfds is a _hint_ about the maximum number of struct pollfd
   structures you may require - you can always ask for more in
   *nfds_io. */
extern void register_for_poll(void *st, beforepoll_fn *before,
			      afterpoll_fn *after, int32_t max_nfds,
			      cstring_t desc);

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
    /* Keep this last: */
    NR_PHASES,
};

typedef void hook_fn(void *self, uint32_t newphase);
bool_t add_hook(uint32_t phase, hook_fn *f, void *state);
bool_t remove_hook(uint32_t phase, hook_fn *f, void *state);

extern uint32_t current_phase;
extern void enter_phase(uint32_t new_phase);

/* Some features (like netlink 'soft' routes) require that secnet
   retain root privileges.  They should indicate that here when
   appropriate. */
extern bool_t require_root_privileges;
extern cstring_t require_root_privileges_explanation;

/***** END of program lifetime support *****/

/***** MODULE support *****/

/* Module initialisation function type - modules export one function of
   this type which is called to initialise them. For dynamically loaded
   modules it's called "secnet_module". */
typedef void init_module(dict_t *dict);

extern void init_builtin_modules(dict_t *dict);

extern init_module resolver_module;
extern init_module random_module;
extern init_module udp_module;
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

/***** END of module support *****/

/***** CLOSURE TYPES and interface definitions *****/

#define CL_PURE         0
#define CL_RESOLVER     1
#define CL_RANDOMSRC    2
#define CL_RSAPUBKEY    3
#define CL_RSAPRIVKEY   4
#define CL_COMM         5
#define CL_IPIF         6
#define CL_LOG          7
#define CL_SITE         8
#define CL_TRANSFORM    9
#define CL_DH          11
#define CL_HASH        12
#define CL_BUFFER      13
#define CL_NETLINK     14

struct buffer_if;

/* PURE closure requires no interface */

/* RESOLVER interface */

/* Answers to queries are delivered to a function of this
   type. 'address' will be NULL if there was a problem with the query. It
   will be freed once resolve_answer_fn returns.  naddrs is the actual
   size of the array at addrs; was_naddrs is the number of addresses
   actually found in the DNS, which may be bigger if addrs is equal
   to MAX_PEER_ADDRS (ie there were too many). */
typedef void resolve_answer_fn(void *st, const struct comm_addr *addrs,
			       int naddrs, int was_naddrs);
typedef bool_t resolve_request_fn(void *st, cstring_t name,
				  int remoteport, struct comm_if *comm,
				  resolve_answer_fn *cb, void *cst);
struct resolver_if {
    void *st;
    resolve_request_fn *request;
};

/* RANDOMSRC interface */

/* Return some random data. Returns TRUE for success. */
typedef bool_t random_fn(void *st, int32_t bytes, uint8_t *buff);

struct random_if {
    void *st;
    bool_t blocking;
    random_fn *generate;
};

/* RSAPUBKEY interface */

typedef bool_t rsa_checksig_fn(void *st, uint8_t *data, int32_t datalen,
			       cstring_t signature);
struct rsapubkey_if {
    void *st;
    rsa_checksig_fn *check;
};

/* RSAPRIVKEY interface */

typedef string_t rsa_makesig_fn(void *st, uint8_t *data, int32_t datalen);
struct rsaprivkey_if {
    void *st;
    rsa_makesig_fn *sign;
};

/* COMM interface */

struct comm_addr {
    /* This struct is pure data; in particular comm's clients may
       freely copy it. */
    struct comm_if *comm;
    union iaddr ia;
};

/* Return True if the packet was processed, and shouldn't be passed to
   any other potential receivers. */
typedef bool_t comm_notify_fn(void *state, struct buffer_if *buf,
			      const struct comm_addr *source);
typedef void comm_request_notify_fn(void *commst, void *nst,
				    comm_notify_fn *fn);
typedef void comm_release_notify_fn(void *commst, void *nst,
				    comm_notify_fn *fn);
typedef bool_t comm_sendmsg_fn(void *commst, struct buffer_if *buf,
			       const struct comm_addr *dest);
  /* Only returns false if (we know that) the local network
   * environment is such that this address cannot work; transient
   * or unknown/unexpected failures return true. */
typedef const char *comm_addr_to_string_fn(void *commst,
					   const struct comm_addr *ca);
        /* Returned string is in a static buffer. */
struct comm_if {
    void *st;
    comm_request_notify_fn *request_notify;
    comm_release_notify_fn *release_notify;
    comm_sendmsg_fn *sendmsg;
    comm_addr_to_string_fn *addr_to_string;
};

bool_t iaddr_equal(const union iaddr *ia, const union iaddr *ib);

static inline const char *comm_addr_to_string(const struct comm_addr *ca)
{
    return ca->comm->addr_to_string(ca->comm->st, ca);
}

static inline bool_t comm_addr_equal(const struct comm_addr *a,
				     const struct comm_addr *b)
{
    return a->comm==b->comm && iaddr_equal(&a->ia,&b->ia);
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
/* Returns:
 *   0: all is well
 *   1: for any other problem
 *   2: message decrypted but sequence number was out of range
 */
typedef uint32_t transform_apply_fn(void *st, struct buffer_if *buf,
				    const char **errmsg);

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
    int capab_transformnum;
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

typedef void *hash_init_fn(void);
typedef void hash_update_fn(void *st, const void *buf, int32_t len);
typedef void hash_final_fn(void *st, uint8_t *digest);
struct hash_if {
    int32_t len; /* Hash output length in bytes */
    hash_init_fn *init;
    hash_update_fn *update;
    hash_final_fn *final;
};

/* BUFFER interface */

struct buffer_if {
    bool_t free;
    cstring_t owner; /* Set to constant string */
    uint32_t flags; /* How paranoid should we be? */
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

/* The cfgfatal() family of functions require messages that end in '\n' */
extern NORETURN(cfgfatal(struct cloc loc, cstring_t facility,
			 const char *message, ...)) FORMAT(printf,3,4);
extern void cfgfile_postreadcheck(struct cloc loc, FILE *f);
extern NORETURN(vcfgfatal_maybefile(FILE *maybe_f, struct cloc loc,
				    cstring_t facility, const char *message,
				    va_list))
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

/*
 * void COPY_OBJ(  OBJECT& dst, const OBJECT& src);
 * void COPY_ARRAY(OBJECT *dst, const OBJECT *src, INTEGER count);
 *   // Typesafe: we check that the type OBJECT is the same in both cases.
 *   // It is OK to use COPY_OBJ on an array object, provided it's
 *   // _actually_ the whole array object and not decayed into a
 *   // pointer (e.g. a formal parameter).
 */
#define COPY_OBJ(dst,src) \
    (&(dst)==&(src), memcpy(&(dst),&(src),sizeof((dst))))
#define COPY_ARRAY(dst,src,count) \
    (&(dst)[0]==&(src)[0], memcpy((dst),(src),sizeof((dst)[0])*(count)))

#endif /* secnet_h */
