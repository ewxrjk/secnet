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
/* Name resolution using adns */

#include <errno.h>
#include "secnet.h"
#include "util.h"
#ifndef HAVE_LIBADNS
#error secnet requires ADNS version 1.0 or above
#endif
#include <adns.h>
#include <arpa/inet.h>
#include <string.h>


struct adns {
    closure_t cl;
    struct resolver_if ops;
    struct cloc loc;
    adns_state ast;
};

struct query {
    void *cst;
    const char *name;
    int port;
    struct comm_if *comm;
    resolve_answer_fn *answer;
    adns_query query;
};

static resolve_request_fn resolve_request;
static bool_t resolve_request(void *sst, cstring_t name,
			      int port, struct comm_if *comm,
			      resolve_answer_fn *cb, void *cst)
{
    struct adns *st=sst;
    struct query *q;
    int rv;
    const int maxlitlen=
#ifdef CONFIG_IPV6
	ADNS_ADDR2TEXT_BUFLEN*2
#else
	50
#endif
	;
    ssize_t l=strlen(name);
    if (name[0]=='[' && l<maxlitlen && l>2 && name[l-1]==']') {
	char trimmed[maxlitlen+1];
	memcpy(trimmed,name+1,l-2);
	trimmed[l-2]=0;
	struct comm_addr ca;
	ca.comm=comm;
	ca.ix=-1;
#ifdef CONFIG_IPV6
	socklen_t salen=sizeof(ca.ia);
	rv=adns_text2addr(trimmed, port, adns_qf_addrlit_ipv4_quadonly,
			  &ca.ia.sa, &salen);
	assert(rv!=ENOSPC);
	if (rv) {
	    char msg[250];
	    snprintf(msg,sizeof(msg),"invalid address literal: %s",
		     strerror(rv));
	    msg[sizeof(msg)-1]=0;
	    cb(cst,0,0,0,name,msg);
	} else {
	    cb(cst,&ca,1,1,name,0);
	}
#else
	ca.ia.sin.sin_family=AF_INET;
	ca.ia.sin.sin_port=htons(port);
	if (inet_aton(trimmed,&ca.ia.sin.sin_addr))
	    cb(cst,&ca,1,1,name,0);
	else
	    cb(cst,0,0,0,name,"invalid IP address");
#endif
	return True;
    }

    NEW(q);
    q->cst=cst;
    q->comm=comm;
    q->port=port;
    q->name=name;
    q->answer=cb;

    rv=adns_submit(st->ast, name, adns_r_addr, 0, q, &q->query);
    if (rv) {
        Message(M_WARNING,
		"resolver: failed to submit lookup for %s: %s",name,
		adns_strerror(rv));
	free(q);
	return False;
    }

    return True;
}

static int resolver_beforepoll(void *sst, struct pollfd *fds, int *nfds_io,
			       int *timeout_io)
{
    struct adns *st=sst;
    return adns_beforepoll(st->ast, fds, nfds_io, timeout_io, tv_now);
}

static void resolver_afterpoll(void *sst, struct pollfd *fds, int nfds)
{
    struct adns *st=sst;
    adns_query aq;
    adns_answer *ans;
    void *qp;
    struct query *q;
    int rv;

    adns_afterpoll(st->ast, fds, nfds, tv_now);

    while (True) {
	aq=NULL;
	rv=adns_check(st->ast, &aq, &ans, &qp);
	if (rv==0) {
	    q=qp;
	    if (ans->status!=adns_s_ok) {
		q->answer(q->cst,NULL,0,0,q->name,adns_strerror(ans->status));
		free(q);
		free(ans);
	    } else {
		int rslot, wslot, total;
		int ca_len=MIN(ans->nrrs,MAX_PEER_ADDRS);
		struct comm_addr ca_buf[ca_len];
		for (rslot=0, wslot=0, total=0;
		     rslot<ans->nrrs;
		     rslot++) {
		    total++;
		    if (!(wslot<ca_len)) continue;
		    adns_rr_addr *ra=&ans->rrs.addr[rslot];
		    struct comm_addr *ca=&ca_buf[wslot];
		    ca->comm=q->comm;
		    ca->ix=-1;
		    assert(ra->len <= (int)sizeof(ca->ia));
		    memcpy(&ca->ia,&ra->addr,ra->len);
		    switch (ra->addr.sa.sa_family) {
		    case AF_INET:
			assert(ra->len == sizeof(ca->ia.sin));
			ca->ia.sin.sin_port=htons(q->port);
			break;
#ifdef CONFIG_IPV6
		    case AF_INET6:
			assert(ra->len == sizeof(ca->ia.sin6));
			ca->ia.sin6.sin6_port=htons(q->port);
			break;
#endif /*CONFIG_IPV6*/
		    default:
			/* silently skip unexpected AFs from adns */
			continue;
		    }
		    wslot++;
		}
		q->answer(q->cst,ca_buf,wslot,total,q->name,0);
		free(q);
		free(ans);
	    }
	} else if (rv==EAGAIN || rv==ESRCH) {
	    break;
	} else {
	    fatal("resolver_afterpoll: adns_check() returned %d",rv);
	}
    }

    return;
}

/* Initialise adns, using parameters supplied */
static list_t *adnsresolver_apply(closure_t *self, struct cloc loc,
				  dict_t *context, list_t *args)
{
    struct adns *st;
    dict_t *d;
    item_t *i;
    string_t conf;

    NEW(st);
    st->cl.description="adns";
    st->cl.type=CL_RESOLVER;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->loc=loc;
    st->ops.st=st;
    st->ops.request=resolve_request;

    i=list_elem(args,0);
    if (!i || i->type!=t_dict) {
	cfgfatal(st->loc,"adns","first argument must be a dictionary\n");
    }
    d=i->data.dict;
    conf=dict_read_string(d,"config",False,"adns",loc);

    if (conf) {
	if (adns_init_strcfg(&st->ast, 0, 0, conf)) {
	    fatal_perror("Failed to initialise ADNS");
	}
    } else {
	if (adns_init(&st->ast, 0, 0)) {
	    fatal_perror("Failed to initialise ADNS");
	}
    }

    register_for_poll(st, resolver_beforepoll, resolver_afterpoll,
		      "resolver");

    return new_closure(&st->cl);
}

void resolver_module(dict_t *dict)
{
    add_closure(dict,"adns",adnsresolver_apply);
}
