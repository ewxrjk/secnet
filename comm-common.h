/*
 * This file is part of secnet.
 * See README for full list of copyright holders.
 *
 * secnet is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version d of the License, or
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

#ifndef COMM_COMMON_H
#define COMM_COMMON_H

#include "secnet.h"
#include "util.h"

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
    NEW(st);						\
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

#define MAX_AF MAX_RAW(AF_INET6,AF_INET)

struct udpsock {
    union iaddr addr;
    int fd;
    bool_t experienced[/*0=recv,1=send*/2][MAX_AF+1][/*success?*/2];
};

struct udpsocks {
    int n_socks;
    struct udpsock socks[UDP_MAX_SOCKETS];
    /* private for udp_socks_* */
    struct udpcommon *uc; /* link to parent, for cfg, notify list, etc. */
    struct poll_interest *interest;
    const char *desc;
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
  /* Caller should have filled in ->addr.  Fills in us->fd,
     ->experienced; updates ->addr.  Logs any errors with lg_[v]perror. */
bool_t udp_import_socket(struct udpcommon *uc, struct udpsock *us,
			 int failmsgclass, int fd);
  /* Like udp_make_socket, but caller provides fd.  fd is not closed
     on error */

void udp_destroy_socket(struct udpcommon *uc, struct udpsock *us);
  /* Idempotent.  No errors are possible. */

const char *af_name(int af);
void udp_sock_experienced(struct log_if *lg, struct udpcommon *uc,
			  struct udpsocks *socks, struct udpsock *us,
			  const union iaddr *dest, int af /* 0 means any */,
			  int r, int errnoval);

void udp_socks_register(struct udpcommon *uc, struct udpsocks *socks,
			const char *desc);
void udp_socks_deregister(struct udpcommon *uc, struct udpsocks *socks);
void udp_socks_childpersist(struct udpcommon *uc, struct udpsocks *socks);

#define UDP_APPLY_STANDARD(st,uc,desc)					\
    (uc)->use_proxy=False;						\
    (uc)->authbind=dict_read_string(d,"authbind",False,"udp",(uc)->cc.loc); \
    (uc)->port=dict_read_number(d,"port",False,"udp",(uc)->cc.loc,0)
    /* void UDP_APPLY_STANDARD(SOMETHING *st, struct udpcommon *uc,
     *                         const char *desc);
     *   // Expects in scope:  dict_t *d=...;   as from COMM_APPLY_STANDARD
     */

#endif /*COMM_COMMON_H*/
