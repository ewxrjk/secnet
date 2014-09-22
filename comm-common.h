
#ifndef COMM_COMMON_H
#define COMM_COMMON_H

#include "secnet.h"

/*----- for all comms -----*/

struct comm_notify_entry {
    comm_notify_fn *fn;
    void *state;
    LIST_ENTRY(comm_notify_entry) entry;
};
LIST_HEAD(comm_notify_list, comm_notify_entry) notify;

struct commcommon { /* must be first so that void* is comm_common* */
    closure_t cl;
    struct comm_if ops;
    struct cloc loc;
    struct comm_notify_list notify;
    struct buffer_if *rbuf;
};

void comm_request_notify(void *commst, void *nst, comm_notify_fn *fn);
void comm_release_notify(void *commst, void *nst, comm_notify_fn *fn);

bool_t comm_notify(struct comm_notify_list *notify, struct buffer_if *buf,
		   const struct comm_addr *ca);
  /* Either: returns True, with message delivered and buffer freed.
   * Or: False, if no-one wanted it - buffer still allocd'd.
   * Ie, like comm_notify_fn. */

void comm_apply(struct commcommon *cc, void *st);

#define COMM_APPLY(st,cc,prefix,desc,loc)		\
    (st)=safe_malloc(sizeof(*(st)), desc "_apply");	\
    (cc)->loc=loc;					\
    (cc)->cl.description=desc;				\
    (cc)->ops.sendmsg=prefix##sendmsg;			\
    (cc)->ops.addr_to_string=prefix##addr_to_string;	\
    comm_apply((cc),(st))
   /* void COMM_APPLY(SOMETHING *st, struct commcommon *FUNCTIONOF(st),
    *                 prefix, "DESC", struct cloc loc);
    *   // Expects in scope: prefix##sendmsg, prefix##addr_to_string.
    */

#define COMM_APPLY_STANDARD(st,cc,desc,args)				\
    item_t *item=list_elem(args,0);					\
    if (!item || item->type!=t_dict) {					\
	cfgfatal((cc)->loc,desc,"first argument must be a dictionary\n"); \
    }									\
    dict_t *d=item->data.dict;						\
    (cc)->rbuf=find_cl_if(d,"buffer",CL_BUFFER,True,desc,(cc)->loc)
    /* void COMM_APPLY_STANDARD(SOMETHING *st, struct commcommon *cc,
     *                          const char *desc, list_t *args);
     *   // Declares:
     *   //    item_t *item = <undefined>;
     *   //    dict_t *dict = <construction dictionary argument>;
     */

/*----- for udp-based comms -----*/

#define UDP_MAX_SOCKETS 3 /* 2 ought to do really */

struct udpsock {
    union iaddr addr;
    int fd;
};

struct udpsocks {
    int n_socks;
    struct udpsock socks[UDP_MAX_SOCKETS];
    /* private for udp_socks_* */
    struct udpcommon *uc; /* link to parent, for cfg, notify list, etc. */
};

struct udpcommon {
    struct commcommon cc;
    int port;
    string_t authbind;
    bool_t use_proxy;
    union iaddr proxy;
};

bool_t udp_make_socket(struct udpcommon *uc, struct udpsock *us,
		       int failmsgclass);
  /* Fills in us->fd.  Logs any errors with lg_[v]perror. */

void udp_socks_register(struct udpcommon *uc, struct udpsocks *socks);

#define UDP_APPLY_STANDARD(st,uc,desc)					\
    (uc)->use_proxy=False;						\
    (uc)->authbind=dict_read_string(d,"authbind",False,"udp",(uc)->cc.loc); \
    (uc)->port=dict_read_number(d,"port",True,"udp",(uc)->cc.loc,0)
    /* void UDP_APPLY_STANDARD(SOMETHING *st, struct udpcommon *uc,
     *                         const char *desc);
     *   // Expects in scope:  dict_t *d=...;   as from COMM_APPLY_STANDARD
     */

#endif /*COMM_COMMON_H*/
