/* Core interface of secnet, to be used by all modules */

#ifndef secnet_h
#define secnet_h

#include "config.h"
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>

/*
 * Macros added by SGT for endianness-independence
 */
#define GET_32BIT_MSB_FIRST(cp) \
  (((unsigned long)(unsigned char)(cp)[0] << 24) | \
  ((unsigned long)(unsigned char)(cp)[1] << 16) | \
  ((unsigned long)(unsigned char)(cp)[2] << 8) | \
  ((unsigned long)(unsigned char)(cp)[3]))

#define PUT_32BIT_MSB_FIRST(cp, value) ( \
  (cp)[0] = (char)((value) >> 24), \
  (cp)[1] = (char)((value) >> 16), \
  (cp)[2] = (char)((value) >> 8), \
  (cp)[3] = (char)(value) )

typedef enum {False,True} bool_t;

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
    const char *file;
    int line;
};

/* Modules export closures, which can be invoked from the configuration file.
   "Invoking" a closure usually returns another closure (of a different
   type), but can actually return any configuration object. */
typedef list_t *(apply_fn)(closure_t *self, struct cloc loc,
			   dict_t *context, list_t *data);
struct closure {
    const char *description; /* For debugging */
    uint32_t type; /* Central registry... */
    apply_fn *apply;
    void *interface; /* Interface for use inside secnet; depends on type */
};

enum types { t_null, t_bool, t_string, t_number, t_dict, t_closure };
struct item {
    enum types type;
    union {
	bool_t bool;
	char *string;
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
extern list_t *dict_lookup(dict_t *dict, const char *key);
/* Lookup a value in just the specified dictionary */
extern list_t *dict_lookup_primitive(dict_t *dict, const char *key);
/* Add a value to the specified dictionary */
extern void dict_add(dict_t *dict, const char *key, list_t *val);
/* Obtain an array of keys in the dictionary. malloced; caller frees */
extern const char **dict_keys(dict_t *dict);

/* List-manipulation functions */
extern list_t *list_new(void);
extern int32_t list_length(list_t *a);
extern list_t *list_append(list_t *a, item_t *i);
extern list_t *list_append_list(list_t *a, list_t *b);
/* Returns an item from the list (index starts at 0), or NULL */
extern item_t *list_elem(list_t *l, int32_t index);

/* Convenience functions */
extern list_t *new_closure(closure_t *cl);
extern void add_closure(dict_t *dict, const char *name, apply_fn apply);
extern void *find_cl_if(dict_t *dict, const char *name, uint32_t type,
			bool_t fail_if_invalid, const char *desc,
			struct cloc loc);
extern item_t *dict_find_item(dict_t *dict, const char *key, bool_t required,
			      const char *desc, struct cloc loc);
extern char *dict_read_string(dict_t *dict, const char *key, bool_t required,
			      const char *desc, struct cloc loc);
extern uint32_t dict_read_number(dict_t *dict, const char *key, bool_t required,
				 const char *desc, struct cloc loc,
				 uint32_t def);
  /* return value can safely be assigned to int32_t */
extern bool_t dict_read_bool(dict_t *dict, const char *key, bool_t required,
			     const char *desc, struct cloc loc, bool_t def);
struct flagstr {
    const char *name;
    uint32_t value;
};
extern uint32_t string_to_word(const char *s, struct cloc loc,
			       struct flagstr *f, const char *desc);
extern uint32_t string_list_to_word(list_t *l, struct flagstr *f,
				    const char *desc);

/***** END of configuration support *****/

/***** UTILITY functions *****/

extern char *safe_strdup(const char *string, const char *message);
extern void *safe_malloc(size_t size, const char *message);
extern void *safe_malloc_ary(size_t size, size_t count, const char *message);

#define NEW(WHAT, MESSAGE) ((WHAT) = safe_malloc(sizeof *(WHAT), MESSAGE))
#define NEWARRAY(WHAT, N, MESSAGE) ((WHAT) = safe_malloc_ary(sizeof *(WHAT), (N), MESSAGE))

extern int sys_cmd(const char *file, const char *argc, ...);

extern uint64_t now_global;
extern struct timeval tv_now_global;

static const uint64_t       *const now    = &now_global;
static const struct timeval *const tv_now = &tv_now_global;

/* "now" is current program time, in milliseconds. It is derived
   from tv_now. Both are provided by the event loop. */

/***** END of utility functions *****/

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
			      const char *desc);

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
extern const char *require_root_privileges_explanation;

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
extern init_module transform_module;
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
   will be freed once resolve_answer_fn returns. It is in network byte
   order. */
/* XXX extend to be able to provide multiple answers */
typedef void resolve_answer_fn(void *st, struct in_addr *addr);
typedef bool_t resolve_request_fn(void *st, const char *name,
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
			       const char *signature);
struct rsapubkey_if {
    void *st;
    rsa_checksig_fn *check;
};

/* RSAPRIVKEY interface */

typedef char *rsa_makesig_fn(void *st, uint8_t *data, int32_t datalen);
struct rsaprivkey_if {
    void *st;
    rsa_makesig_fn *sign;
};

/* COMM interface */

struct comm_addr {
    /* This struct is pure data; in particular comm's clients may
       freely copy it. */
    /* Everyone is also guaranteed that all padding is set to zero, ie
       that comm_addrs referring to semantically identical peers will
       compare equal with memcmp.  Anyone who constructs a comm_addr
       must start by memsetting it with FILLZERO, or some
       equivalent. */
    struct comm_if *comm;
    struct sockaddr_in sin;
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
typedef const char *comm_addr_to_string_fn(void *commst,
					   const struct comm_addr *ca);
        /* Returned string is in a static buffer. */
struct comm_if {
    void *st;
    int32_t min_start_pad;
    int32_t min_end_pad;
    comm_request_notify_fn *request_notify;
    comm_release_notify_fn *release_notify;
    comm_sendmsg_fn *sendmsg;
    comm_addr_to_string_fn *addr_to_string;
};

/* LOG interface */

typedef void log_msg_fn(void *st, int class, const char *message, ...);
typedef void log_vmsg_fn(void *st, int class, const char *message,
			 va_list args);
struct log_if {
    void *st;
    log_msg_fn *log;
    log_vmsg_fn *vlog;
};
/* (convenience functions, defined in util.c) */
extern void slilog(struct log_if *lf, int class, const char *message, ...)
FORMAT(printf,3,4);
extern void vslilog(struct log_if *lf, int class, const char *message, va_list)
FORMAT(printf,3,0);

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
   data to start or end. Maximum amount of data to be added specified
   in max_start_pad and max_end_pad. (Reverse transformations decrease
   length, of course.)  Transformations may be key-dependent, in which
   case key material is passed in at initialisation time. They may
   also depend on internal factors (eg. time) and keep internal
   state. A struct transform_if only represents a particular type of
   transformation; instances of the transformation (eg. with
   particular key material) have a different C type. */

typedef struct transform_inst_if *transform_createinstance_fn(void *st);
typedef bool_t transform_setkey_fn(void *st, uint8_t *key, int32_t keylen);
typedef void transform_delkey_fn(void *st);
typedef void transform_destroyinstance_fn(void *st);
/* Returns 0 for 'all is well', any other value for a problem */
typedef uint32_t transform_apply_fn(void *st, struct buffer_if *buf,
				    const char **errmsg);

struct transform_inst_if {
    void *st;
    transform_setkey_fn *setkey;
    transform_delkey_fn *delkey;
    transform_apply_fn *forwards;
    transform_apply_fn *reverse;
    transform_destroyinstance_fn *destroy;
};

struct transform_if {
    void *st;
    int32_t max_start_pad; /* these three are all <<< INT_MAX */
    int32_t max_end_pad;
    int32_t keylen;
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
#define LINK_QUALITY_DOWN 0   /* No chance of a packet being delivered */
#define LINK_QUALITY_DOWN_STALE_ADDRESS 1 /* Link down, old address information */
#define LINK_QUALITY_DOWN_CURRENT_ADDRESS 2 /* Link down, current address information */
#define LINK_QUALITY_UP 3     /* Link active */
#define MAXIMUM_LINK_QUALITY 3
typedef void netlink_link_quality_fn(void *st, uint32_t quality);
typedef void netlink_register_fn(void *st, netlink_deliver_fn *deliver,
				 void *dst, int32_t max_start_pad,
				 int32_t max_end_pad);
typedef void netlink_output_config_fn(void *st, struct buffer_if *buf);
typedef bool_t netlink_check_config_fn(void *st, struct buffer_if *buf);
typedef void netlink_set_mtu_fn(void *st, int32_t new_mtu);
struct netlink_if {
    void *st;
    netlink_register_fn *reg;
    netlink_deliver_fn *deliver;
    netlink_link_quality_fn *set_quality;
    netlink_output_config_fn *output_config;
    netlink_check_config_fn *check_config;
    netlink_set_mtu_fn *set_mtu;
};

/* DH interface */

/* Returns public key as a malloced hex string */
typedef char *dh_makepublic_fn(void *st, uint8_t *secret,
			       int32_t secretlen);
/* Fills buffer (up to buflen) with shared secret */
typedef void dh_makeshared_fn(void *st, uint8_t *secret,
			      int32_t secretlen, const char *rempublic,
			      uint8_t *sharedsecret, int32_t buflen);
struct dh_if {
    void *st;
    int32_t len; /* Approximate size of modulus in bytes */
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
    const char *owner; /* Set to constant string */
    uint32_t flags; /* How paranoid should we be? */
    struct cloc loc; /* Where we were defined */
    uint8_t *base;
    uint8_t *start;
    int32_t size; /* Size of buffer contents */
    int32_t len; /* Total length allocated at base */
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
extern NORETURN(fatal(const char *message, ...));
extern NORETURN(fatal_perror(const char *message, ...));
extern NORETURN(fatal_status(int status, const char *message, ...));
extern NORETURN(fatal_perror_status(int status, const char *message, ...));

/* The cfgfatal() family of functions require messages that end in '\n' */
extern NORETURN(cfgfatal(struct cloc loc, const char *facility,
			 const char *message, ...));
extern void cfgfile_postreadcheck(struct cloc loc, FILE *f);
extern NORETURN(vcfgfatal_maybefile(FILE *maybe_f, struct cloc loc,
				    const char *facility, const char *message,
				    va_list));
extern NORETURN(cfgfatal_maybefile(FILE *maybe_f, struct cloc loc,
				   const char *facility,
				   const char *message, ...));

extern void Message(uint32_t class, const char *message, ...)
    FORMAT(printf,2,3);
extern void log_from_fd(int fd, const char *prefix, struct log_if *log);

/***** END of log functions *****/

#define STRING2(x) #x
#define STRING(x) STRING2(x)

#define FILLZERO(obj) (memset(&(obj),0,sizeof((obj))))

#endif /* secnet_h */
