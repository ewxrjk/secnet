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
