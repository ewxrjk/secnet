/*
 * osdep.c
 * - portability routines
 */
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

#include "config.h"
#include "osdep.h"
#include "secnet.h"
#include "util.h"

#ifndef HAVE_FMEMOPEN
# ifdef HAVE_FUNOPEN

struct fmemopen_state {
    const char *bufp;
    size_t remain;
};

static int fmemopen_readfn(void *sst, char *out, int sz)
{
    struct fmemopen_state *st=sst;
    assert(sz>=0);
    int now=MIN((size_t)sz,st->remain);
    memcpy(out,st->bufp,now);
    st->remain-=now;
    return now;
}
static int fmemopen_close(void *sst) { free(sst); return 0; }

FILE *fmemopen(void *buf, size_t size, const char *mode)
{
    /* this is just a fake plastic imitation */
    assert(!strcmp(mode,"r"));
    struct fmemopen_state *st;
    NEW(st);
    st->bufp=buf;
    st->remain=size;
    FILE *f=funopen(st,fmemopen_readfn,0,0,fmemopen_close);
    if (!f) free(st);
    return f;
}

# else /* HAVE_FUNOPEN */
#  error no fmemopen, no funopen, cannot proceed
# endif

#endif /* HAVE_FMEMOPEN */
