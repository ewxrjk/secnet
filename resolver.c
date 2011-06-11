/* Name resolution using adns */

#include <errno.h>
#include "secnet.h"
#ifndef HAVE_LIBADNS
#error secnet requires ADNS version 1.0 or above
#endif
#include <adns.h>


struct adns {
    closure_t cl;
    struct resolver_if ops;
    struct cloc loc;
    adns_state ast;
};

struct query {
    void *cst;
    resolve_answer_fn *answer;
    adns_query query;
};

static resolve_request_fn resolve_request;
static bool_t resolve_request(void *sst, cstring_t name,
			      resolve_answer_fn *cb, void *cst)
{
    struct adns *st=sst;
    struct query *q;
    int rv;

    q=safe_malloc(sizeof *q,"resolve_request");
    q->cst=cst;
    q->answer=cb;

    rv=adns_submit(st->ast, name, adns_r_a, 0, q, &q->query);

    return rv==0;
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
		q->answer(q->cst,NULL); /* Failure */
		free(q);
		free(ans);
	    } else {
		q->answer(q->cst,ans->rrs.inaddr);
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

    st=safe_malloc(sizeof(*st),"adnsresolver_apply");
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
		      ADNS_POLLFDS_RECOMMENDED+5,"resolver");

    return new_closure(&st->cl);
}

void resolver_module(dict_t *dict)
{
    add_closure(dict,"adns",adnsresolver_apply);
}
