/* Core interface of secnet, to be used by all modules */

#ifndef secnet_h
#define secnet_h

#include "config.h"
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>

typedef char *string_t;
typedef enum {False,True} bool_t;

#define ASSERT(x) do { if (!(x)) { fatal("assertion failed line " __LINE__ \
					 " file " __FILE__ "\n"); } while(0)

/***** SHARED types *****/

/* These are stored in HOST byte order */
struct subnet {
    uint32_t prefix;
    uint32_t mask;
};

struct subnet_list {
    uint32_t entries;
    struct subnet *list;
};

/* Match an address (in HOST byte order) with a subnet list.
   Returns True if matched. */
extern bool_t subnet_match(struct subnet_list *list, uint32_t address);

/***** END of shared types *****/

/***** CONFIGURATION support *****/

typedef struct dict dict_t;        /* Configuration dictionary */
typedef struct closure closure_t;
typedef struct item item_t;
typedef struct list list_t;        /* A list of items */

/* Configuration file location, for error-reporting */
struct cloc {
    string_t file;
    uint32_t line;
};

/* Modules export closures, which can be invoked from the configuration file.
   "Invoking" a closure usually returns another closure (of a different
   type), but can actually return any configuration object. */
typedef list_t *(apply_fn)(closure_t *self, struct cloc loc,
			   dict_t *context, list_t *data);
struct closure {
    string_t description; /* For debugging */
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

struct list {
    item_t *item;
    struct list *next;
};

/* In the following two lookup functions, NULL means 'not found' */
/* Lookup a value in the specified dictionary, or its parents */
extern list_t *dict_lookup(dict_t *dict, string_t key);
/* Lookup a value in just the specified dictionary */
extern list_t *dict_lookup_primitive(dict_t *dict, string_t key);
/* Add a value to the specified dictionary */
extern void dict_add(dict_t *dict, string_t key, list_t *val);
/* Obtain an array of keys in the dictionary. malloced; caller frees */
extern string_t *dict_keys(dict_t *dict);

/* List-manipulation functions */
extern list_t *list_new(void);
extern list_t *list_append(list_t *a, item_t *i);
extern list_t *list_append_list(list_t *a, list_t *b);
/* Returns an item from the list (index starts at 0), or NULL */
extern item_t *list_elem(list_t *l, uint32_t index);

/* Convenience functions */
extern list_t *new_closure(closure_t *cl);
extern void add_closure(dict_t *dict, string_t name, apply_fn apply);
extern void *find_cl_if(dict_t *dict, string_t name, uint32_t type,
			bool_t fail_if_invalid, string_t desc,
			struct cloc loc);
extern item_t *dict_find_item(dict_t *dict, string_t key, bool_t required,
			      string_t desc, struct cloc loc);
extern string_t dict_read_string(dict_t *dict, string_t key, bool_t required,
				 string_t desc, struct cloc loc);
extern uint32_t dict_read_number(dict_t *dict, string_t key, bool_t required,
				 string_t desc, struct cloc loc, uint32_t def);
extern bool_t dict_read_bool(dict_t *dict, string_t key, bool_t required,
			     string_t desc, struct cloc loc, bool_t def);
extern void dict_read_subnet_list(dict_t *dict, string_t key, bool_t required,
				  string_t desc, struct cloc loc,
				  struct subnet_list *sl);
extern uint32_t string_to_ipaddr(item_t *i, string_t desc);

/***** END of configuration support *****/

/***** UTILITY functions *****/

#define M_WARNING	1
#define M_ERROR		2
#define M_FATAL		4
#define M_INFO		8
#define M_DEBUG_CONFIG 16
#define M_DEBUG_PHASE  32

extern void fatal(char *message, ...);
extern void fatal_perror(char *message, ...);
extern void fatal_status(int status, char *message, ...);
extern void fatal_perror_status(int status, char *message, ...);
extern void cfgfatal(struct cloc loc, string_t facility, char *message, ...);

extern char *safe_strdup(char *string, char *message);
extern void *safe_malloc(size_t size, char *message);

extern void Message(uint32_t class, char *message, ...);

extern string_t ipaddr_to_string(uint32_t addr);
extern string_t subnet_to_string(struct subnet *sn);

extern int sys_cmd(const char *file, char *argc, ...);

/***** END of utility functions *****/

/***** SCHEDULING support */

/* "now" is current program time, in milliseconds. It is derived
   (once) from tv_now. If nfds_io is insufficient for your needs, set
   it to the required number and return ERANGE. timeout is in milliseconds;
   if it is too high then lower it. It starts at -1 (==infinite) */
typedef int beforepoll_fn(void *st, struct pollfd *fds, int *nfds_io,
			  int *timeout_io, const struct timeval *tv_now,
			  uint64_t *now);
typedef void afterpoll_fn(void *st, struct pollfd *fds, int nfds,
			  const struct timeval *tv_now, uint64_t *now);

/* Register interest in the main loop of the program. Before a call
   to poll() your supplied beforepoll function will be called. After
   the call to poll() the supplied afterpoll function will be called.
   max_nfds is a _hint_ about the maximum number of struct pollfd
   structures you may require - you can always ask for more in
   *nfds_io. */
extern void register_for_poll(void *st, beforepoll_fn *before,
			      afterpoll_fn *after, uint32_t max_nfds,
			      string_t desc);

/***** END of scheduling support */

/***** PROGRAM LIFETIME support */

/* The secnet program goes through a number of phases in its lifetime.
   Module code may arrange to be called just as various phases are
   entered. */

#define PHASE_INIT          0
#define PHASE_GETOPTS       1  /* Process command-line arguments */
#define PHASE_READCONFIG    2  /* Parse and process configuration file */
#define PHASE_SETUP         3  /* Process information in configuration */
#define PHASE_DROPPRIV      4  /* Last chance for privileged operations */
#define PHASE_RUN           5
#define PHASE_SHUTDOWN      6  /* About to die; delete key material, etc. */
#define NR_PHASES           7

typedef void hook_fn(void *self, uint32_t newphase);
bool_t add_hook(uint32_t phase, hook_fn *f, void *state);
bool_t remove_hook(uint32_t phase, hook_fn *f, void *state);

/***** END of program lifetime support *****/

/***** MODULE support *****/

/* Module initialisation function type - modules export one function of
   this type which is called to initialise them. For dynamically loaded
   modules it's called "secnet_module". */
typedef void (init_module)(dict_t *dict);

/***** END of module support *****/

/***** CLOSURE TYPES and interface definitions *****/

#define CL_PURE        0
#define CL_RESOLVER    1
#define CL_RANDOMSRC   2
#define CL_RSAPUBKEY   3
#define CL_RSAPRIVKEY  4
#define CL_COMM        5
#define CL_IPIF        6
#define CL_LOG         7
#define CL_SITE        8
#define CL_TRANSFORM   9
#define CL_NETLINK    10
#define CL_DH         11
#define CL_HASH       12
#define CL_BUFFER     13

struct buffer_if;

/* PURE closure requires no interface */

/* RESOLVER interface */

/* Answers to queries are delivered to a function of this
   type. 'address' will be NULL if there was a problem with the query. It
   will be freed once resolve_answer_fn returns. It is in network byte
   order. */
typedef void resolve_answer_fn(void *st, struct in_addr *addr);
typedef bool_t resolve_request_fn(void *st, string_t name,
				  resolve_answer_fn *cb, void *cst);
struct resolver_if {
    void *st;
    resolve_request_fn *request;
};

/* RANDOMSRC interface */

/* Return some random data. Returns TRUE for success. */
typedef bool_t random_fn(void *st, uint32_t bytes, uint8_t *buff);

struct random_if {
    void *st;
    bool_t blocking;
    random_fn *generate;
};

/* RSAPUBKEY interface */

typedef bool_t rsa_checksig_fn(void *st, uint8_t *data, uint32_t datalen,
			       string_t signature);
struct rsapubkey_if {
    void *st;
    rsa_checksig_fn *check;
};

/* RSAPRIVKEY interface */

typedef string_t rsa_makesig_fn(void *st, uint8_t *data, uint32_t datalen);
struct rsaprivkey_if {
    void *st;
    rsa_makesig_fn *sign;
};

/* COMM interface */

/* Return True if the packet was processed, and shouldn't be passed to
   any other potential receivers. */
typedef bool_t comm_notify_fn(void *state, struct buffer_if *buf,
			    struct sockaddr_in *source);
typedef void comm_request_notify_fn(void *commst, void *nst,
				    comm_notify_fn *fn);
typedef void comm_release_notify_fn(void *commst, void *nst,
				    comm_notify_fn *fn);
typedef bool_t comm_sendmsg_fn(void *commst, struct buffer_if *buf,
			       struct sockaddr_in *dest);
struct comm_if {
    void *st;
    comm_request_notify_fn *request_notify;
    comm_release_notify_fn *release_notify;
    comm_sendmsg_fn *sendmsg;
};

/* LOG interface */

typedef void log_msg_fn(void *st, int priority, char *message, ...);
typedef void log_vmsg_fn(void *st, int priority, char *message, va_list args);
struct log_if {
    void *st;
    log_msg_fn *log;
    log_vmsg_fn *vlog;
};
/* (convenience function, defined in util.c) */
extern void log(struct log_if *lf, int priority, char *message, ...);

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
typedef bool_t transform_setkey_fn(void *st, uint8_t *key, uint32_t keylen);
typedef void transform_delkey_fn(void *st);
typedef void transform_destroyinstance_fn(void *st);
/* Returns 0 for 'all is well', any other value for a problem */
typedef uint32_t transform_apply_fn(void *st, struct buffer_if *buf,
				    char **errmsg);

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
    uint32_t max_start_pad;
    uint32_t max_end_pad;
    uint32_t keylen;
    transform_createinstance_fn *create;
};

/* NETLINK interface */

/* Used by netlink to deliver to site, and by site to deliver to netlink.
   cid is the client identifier returned by netlink_regnets_fn */
typedef void netlink_deliver_fn(void *st, void *cid, struct buffer_if *buf);
/* site code can tell netlink when outgoing packets will be dropped,
   so netlink can generate appropriate ICMP */
typedef void netlink_can_deliver_fn(void *st, void *cid, bool_t can_deliver);
/* Register for packets from specified networks. Return value is client
   identifier. */
typedef void *netlink_regnets_fn(void *st, struct subnet_list *networks,
				 netlink_deliver_fn *deliver, void *dst,
				 uint32_t max_start_pad, uint32_t max_end_pad,
				 string_t client_name);

struct netlink_if {
    void *st;
    netlink_regnets_fn *regnets;
    netlink_deliver_fn *deliver;
    netlink_can_deliver_fn *set_delivery;
};

/* DH interface */

/* Returns public key as a malloced hex string */
typedef string_t dh_makepublic_fn(void *st, uint8_t *secret,
				  uint32_t secretlen);
/* Fills buffer (up to buflen) with shared secret */
typedef void dh_makeshared_fn(void *st, uint8_t *secret,
			      uint32_t secretlen, string_t rempublic,
			      uint8_t *sharedsecret, uint32_t buflen);
struct dh_if {
    void *st;
    uint32_t len; /* Approximate size of modulus in bytes */
    dh_makepublic_fn *makepublic;
    dh_makeshared_fn *makeshared;
};

/* HASH interface */

typedef void *hash_init_fn(void);
typedef void hash_update_fn(void *st, uint8_t const *buf, uint32_t len);
typedef void hash_final_fn(void *st, uint8_t *digest);
struct hash_if {
    uint32_t len; /* Hash output length in bytes */
    hash_init_fn *init;
    hash_update_fn *update;
    hash_final_fn *final;
};

/* BUFFER interface */

struct buffer_if {
    bool_t free;
    string_t owner; /* Set to constant string */
    uint32_t flags; /* How paranoid should we be? */
    struct cloc loc; /* Where we were defined */
    uint8_t *base;
    uint8_t *start;
    uint32_t size; /* Size of buffer contents */
    uint32_t len; /* Total length allocated at base */
};

#endif /* secnet_h */
