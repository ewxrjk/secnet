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

#ifndef pubkeys_h
#define pubkeys_h

#include "secnet.h"

/*----- shared with site.c -----*/

struct peer_pubkey {
    struct sigkeyid id;
    struct sigpubkey_if *pubkey;
};

struct peer_keyset {
    int refcount;
    serialt serial;
    int nkeys;
    struct peer_pubkey keys[MAX_SIG_KEYS];
};

extern struct peer_keyset *
keyset_load(const char *path, struct buffer_if *data_buf,
	    struct log_if *log, int logcl_enoent);

extern void keyset_dispose(struct peer_keyset **ks);

static inline struct peer_keyset *keyset_dup(struct peer_keyset *in) {
    in->refcount++;
    return in;
}

extern bool_t
pubkey_want(struct peer_keyset *building /* refcount and serial undef */,
	    struct sigkeyid *id, const struct sigscheme_info *scheme);

#endif /* pubkeys_h */
