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

#include "util.h"
#include "base91s/base91.h"
#include "pubkeys.h"
#include "pubkeys.yy.h"

void keyset_dispose(struct peer_keyset **ks_io)
{
    struct peer_keyset *ks=*ks_io;
    if (!ks) return;
    *ks_io=0;
    ks->refcount--;
    assert(ks->refcount>=0);
    if (ks->refcount) return;
    for (int ki=0; ki<ks->nkeys; ki++) {
	struct sigpubkey_if *pk=ks->keys[ki].pubkey;
	pk->dispose(pk->st);
    }
    free(ks);
}

const struct sigscheme_info *sigscheme_lookup(const char *name)
{
    const struct sigscheme_info *scheme;
    for (scheme=sigschemes; scheme->name; scheme++)
	if (!strcmp(name,scheme->name))
	    return scheme;
    return 0;
}

static list_t *makepublic_apply(closure_t *self, struct cloc loc,
				dict_t *context, list_t *args)
{
#define ARG(ix,vn,what)							\
    item_t *vn##_i=list_elem(args,ix);					\
    if (!vn##_i) cfgfatal(loc,"make-public","need " what);		\
    if (vn##_i->type!=t_string) cfgfatal(vn##_i->loc,"make-public",	\
				    what "must be string");		\
    const char *vn=vn##_i->data.string

    ARG(0,algname,"algorithm name");
    ARG(1,b91d,"base91s-encoded public key");

    const struct sigscheme_info *sch=sigscheme_lookup(algname);
    if (!sch) cfgfatal(algname_i->loc,"make-public",
		       "unknown algorithm `%s'",algname);

    size_t b91l=strlen(b91d);
    if (b91l > INT_MAX/4) cfgfatal(algname_i->loc,"make-public",
				      "base91s data unreasonably long");

    struct buffer_if buf;
    buffer_new(&buf,base91s_decode_maxlen(b91l));
    BUF_ALLOC(&buf,"make-public data buf");
    assert(buf.start == buf.base);
    struct base91s b91;
    base91s_init(&b91);
    buf.size= base91s_decode(&b91,b91d,b91l,buf.start);
    buf.size += base91s_decode_end(&b91,buf.start+buf.size);
    assert(buf.size <= buf.alloclen);

    struct cfgfile_log log;
    cfgfile_log_init(&log,loc,"make-public");

    struct sigpubkey_if *pubkey;
    closure_t *cl;
    bool_t ok=sch->loadpub(sch,&buf,&pubkey,&cl,&log.log,loc);
    if (!ok) cfgfatal(loc,"make-public","public key loading failed");

    if (pubkey->sethash) {
	struct hash_if *defhash=
	    find_cl_if(context,"hash",CL_HASH,True,"make-public",loc);
	pubkey->sethash(pubkey->st,defhash);
    }

    BUF_FREE(&buf);
    buffer_destroy(&buf);
    return new_closure(cl);
}

void pubkeys_init(dict_t *dict) {
    add_closure(dict,"make-public",makepublic_apply);
}
