/*
 * util.c
 * - output and logging support
 * - program lifetime support
 * - IP address and subnet munging routines
 * - MPI convenience functions
 */
/*
 *  This file is
 *    Copyright (C) 1995--2001 Stephen Early <steve@greenend.org.uk>
 *
 *  It is part of secnet, which is
 *    Copyright (C) 1995--2001 Stephen Early <steve@greenend.org.uk>
 *    Copyright (C) 1998 Ross Anderson, Eli Biham, Lars Knudsen
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. 
 */

#include "secnet.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>
#include <sys/wait.h>
#include "util.h"
#include "unaligned.h"

#define MIN_BUFFER_SIZE 64
#define DEFAULT_BUFFER_SIZE 4096
#define MAX_BUFFER_SIZE 131072

static const char *hexdigits="0123456789abcdef";

uint32_t current_phase=0;

struct phase_hook {
    hook_fn *fn;
    void *state;
    struct phase_hook *next;
};

static struct phase_hook *hooks[NR_PHASES]={NULL,};

char *safe_strdup(const char *s, const char *message)
{
    char *d;
    d=strdup(s);
    if (!d) {
	fatal_perror(message);
    }
    return d;
}

void *safe_malloc(size_t size, const char *message)
{
    void *r;
    r=malloc(size);
    if (!r) {
	fatal_perror(message);
    }
    return r;
}
void *safe_malloc_ary(size_t size, size_t count, const char *message) {
    if (count >= INT_MAX/size) {
	fatal("array allocation overflow: %s", message);
    }
    return safe_malloc(size*count, message);
}

/* Convert a buffer into its MP_INT representation */
void read_mpbin(MP_INT *a, uint8_t *bin, int binsize)
{
    char *buff;
    int i;

    buff=safe_malloc(binsize*2 + 1,"read_mpbin");

    for (i=0; i<binsize; i++) {
	buff[i*2]=hexdigits[(bin[i] & 0xf0) >> 4];
	buff[i*2+1]=hexdigits[(bin[i] & 0xf)];
    }
    buff[binsize*2]=0;

    mpz_set_str(a, buff, 16);
    free(buff);
}

/* Convert a MP_INT into a hex string */
char *write_mpstring(MP_INT *a)
{
    char *buff;

    buff=safe_malloc(mpz_sizeinbase(a,16)+2,"write_mpstring");
    mpz_get_str(buff, 16, a);
    return buff;
}

static uint8_t hexval(uint8_t c)
{
    switch (c) {
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'a': return 10;
    case 'A': return 10;
    case 'b': return 11;
    case 'B': return 11;
    case 'c': return 12;
    case 'C': return 12;
    case 'd': return 13;
    case 'D': return 13;
    case 'e': return 14;
    case 'E': return 14;
    case 'f': return 15;
    case 'F': return 15;
    }
    return -1;
}

/* Convert a MP_INT into a buffer; return length; truncate if necessary */
int32_t write_mpbin(MP_INT *a, uint8_t *buffer, int32_t buflen)
{
    char *hb;
    int i,j,l;
    
    if (buflen==0) return 0;
    hb=write_mpstring(a);
    
    l=strlen(hb);
    i=0; j=0;
    if (l&1) {
	/* The number starts with a half-byte */
	buffer[i++]=hexval(hb[j++]);
    }
    for (; hb[j] && i<buflen; i++) {
	buffer[i]=(hexval(hb[j])<<4)|hexval(hb[j+1]);
	j+=2;
    }
    free(hb);
    return i;
}

static const char *phases[NR_PHASES]={
    "PHASE_INIT",
    "PHASE_GETOPTS",
    "PHASE_READCONFIG",
    "PHASE_SETUP",
    "PHASE_DAEMONIZE",
    "PHASE_GETRESOURCES",
    "PHASE_DROPPRIV",
    "PHASE_RUN",
    "PHASE_SHUTDOWN"
};

void enter_phase(uint32_t new_phase)
{
    struct phase_hook *i;

    if (hooks[new_phase])
	Message(M_DEBUG_PHASE,"Running hooks for %s...\n", phases[new_phase]);
    current_phase=new_phase;

    for (i=hooks[new_phase]; i; i=i->next)
	i->fn(i->state, new_phase);
    Message(M_DEBUG_PHASE,"Now in %s\n",phases[new_phase]);
}

bool_t add_hook(uint32_t phase, hook_fn *fn, void *state)
{
    struct phase_hook *h;

    h=safe_malloc(sizeof(*h),"add_hook");
    h->fn=fn;
    h->state=state;
    h->next=hooks[phase];
    hooks[phase]=h;
    return True;
}

bool_t remove_hook(uint32_t phase, hook_fn *fn, void *state)
{
    fatal("remove_hook: not implemented");

    return False;
}

void vslilog(struct log_if *lf, int priority, const char *message, va_list ap)
{
    lf->vlog(lf->st,priority,message,ap);
}

void slilog(struct log_if *lf, int priority, const char *message, ...)
{
    va_list ap;
    
    va_start(ap,message);
    vslilog(lf,priority,message,ap);
    va_end(ap);
}

struct buffer {
    closure_t cl;
    struct buffer_if ops;
};

void buffer_assert_free(struct buffer_if *buffer, cstring_t file,
			int line)
{
    if (!buffer->free) {
	fatal("BUF_ASSERT_FREE, %s line %d, owned by %s",
	      file,line,buffer->owner);
    }
}

void buffer_assert_used(struct buffer_if *buffer, cstring_t file,
			int line)
{
    if (buffer->free) {
	fatal("BUF_ASSERT_USED, %s line %d, last owned by %s",
	      file,line,buffer->owner);
    }
}

void buffer_init(struct buffer_if *buffer, int32_t max_start_pad)
{
    buffer->start=buffer->base+max_start_pad;
    buffer->size=0;
}

void *buf_append(struct buffer_if *buf, int32_t amount) {
    void *p;
    assert(buf->size <= buf->len - amount);
    p=buf->start + buf->size;
    buf->size+=amount;
    return p;
}

void *buf_prepend(struct buffer_if *buf, int32_t amount) {
    assert(amount <= buf->start - buf->base);
    buf->size+=amount;
    return buf->start-=amount;
}

void *buf_unappend(struct buffer_if *buf, int32_t amount) {
    if (buf->size < amount) return 0;
    return buf->start+(buf->size-=amount);
}

void *buf_unprepend(struct buffer_if *buf, int32_t amount) {
    void *p;
    if (buf->size < amount) return 0;
    p=buf->start;
    buf->start+=amount;
    buf->size-=amount;
    return p;
}

/* Append a two-byte length and the string to the buffer. Length is in
   network byte order. */
void buf_append_string(struct buffer_if *buf, cstring_t s)
{
    size_t len;

    len=strlen(s);
    /* fixme: if string is longer than 65535, result is a corrupted packet */
    buf_append_uint16(buf,len);
    memcpy(buf_append(buf,len),s,len);
}

void buffer_new(struct buffer_if *buf, int32_t len)
{
    buf->free=True;
    buf->owner=NULL;
    buf->flags=0;
    buf->loc.file=NULL;
    buf->loc.line=0;
    buf->size=0;
    buf->len=len;
    buf->start=NULL;
    buf->base=safe_malloc(len,"buffer_new");
}

void buffer_copy(struct buffer_if *dst, const struct buffer_if *src)
{
    if (dst->len < src->len) {
	dst->base=realloc(dst->base,src->len);
	if (!dst->base) fatal_perror("buffer_copy");
	dst->len = src->len;
    }
    dst->start = dst->base + (src->start - src->base);
    dst->size = src->size;
    memcpy(dst->start, src->start, dst->size);
}

static list_t *buffer_apply(closure_t *self, struct cloc loc, dict_t *context,
			    list_t *args)
{
    struct buffer *st;
    item_t *item;
    dict_t *dict;
    bool_t lockdown=False;
    uint32_t len=DEFAULT_BUFFER_SIZE;
    
    st=safe_malloc(sizeof(*st),"buffer_apply");
    st->cl.description="buffer";
    st->cl.type=CL_BUFFER;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;

    /* First argument, if present, is buffer length */
    item=list_elem(args,0);
    if (item) {
	if (item->type!=t_number) {
	    cfgfatal(st->ops.loc,"buffer","first parameter must be a "
		     "number (buffer size)\n");
	}
	len=item->data.number;
	if (len<MIN_BUFFER_SIZE) {
	    cfgfatal(st->ops.loc,"buffer","ludicrously small buffer size\n");
	}
	if (len>MAX_BUFFER_SIZE) {
	    cfgfatal(st->ops.loc,"buffer","ludicrously large buffer size\n");
	}
    }
    /* Second argument, if present, is a dictionary */
    item=list_elem(args,1);
    if (item) {
	if (item->type!=t_dict) {
	    cfgfatal(st->ops.loc,"buffer","second parameter must be a "
		     "dictionary\n");
	}
	dict=item->data.dict;
	lockdown=dict_read_bool(dict,"lockdown",False,"buffer",st->ops.loc,
				False);
    }

    buffer_new(&st->ops,len);
    if (lockdown) {
	/* XXX mlock the buffer if possible */
    }
    
    return new_closure(&st->cl);
}

void util_module(dict_t *dict)
{
    add_closure(dict,"sysbuffer",buffer_apply);
}
