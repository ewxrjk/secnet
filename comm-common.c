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

#include "secnet.h"
#include "comm-common.h"

struct comm_clientinfo *comm_clientinfo_ignore(void *state, dict_t *dict,
					       struct cloc cloc)
{
    return 0;
}

void comm_request_notify(void *commst, void *nst, comm_notify_fn *fn)
{
    struct commcommon *st=commst;
    struct comm_notify_entry *n;
    
    NEW(n);
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

bool_t comm_notify(struct commcommon *cc,
		   struct buffer_if *buf, const struct comm_addr *ca)
{
    struct comm_notify_list *notify = &cc->notify;
    struct comm_notify_entry *n;

    priomsg_reset(&cc->why_unwanted);

    LIST_FOREACH(n, notify, entry) {
	if (n->fn(n->state, buf, ca, &cc->why_unwanted)) {
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
    priomsg_new(&cc->why_unwanted, MAX_NAK_MSG);
}
