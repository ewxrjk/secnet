
#include "secnet.h"
#include "comm-common.h"

void comm_request_notify(void *commst, void *nst, comm_notify_fn *fn)
{
    struct commcommon *st=commst;
    struct comm_notify_entry *n;
    
    n=safe_malloc(sizeof(*n),"comm_request_notify");
    n->fn=fn;
    n->state=nst;
    LIST_INSERT_HEAD(&st->notify, n, entry);
}

void comm_release_notify(void *commst, void *nst, comm_notify_fn *fn)
{
    struct commcommon *st=commst;
    struct comm_notify_entry *n, *t;

    /* XXX untested */
    LIST_FOREACH_SAFE(n, &st->notify, entry, t) {
       if (n->state==nst && n->fn==fn) {
	   LIST_REMOVE(n, entry);
	   free(n);
       }
    }
}

bool_t comm_notify(struct comm_notify_list *notify,
		   struct buffer_if *buf, const struct comm_addr *ca)
{
    struct comm_notify_entry *n;

    LIST_FOREACH(n, notify, entry) {
	if (n->fn(n->state, buf, ca)) {
	    return True;
	}
    }
    return False;
}

void comm_apply(struct commcommon *cc, void *st)
{
    assert(cc==st);
    cc->cl.type=CL_COMM;
    cc->cl.apply=NULL;
    cc->cl.interface=&cc->ops;
    cc->ops.st=cc;
    cc->ops.request_notify=comm_request_notify;
    cc->ops.release_notify=comm_release_notify;
    LIST_INIT(&cc->notify);
    cc->rbuf=NULL;
}
