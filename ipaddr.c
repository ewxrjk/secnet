/* The 'ipset' data structure and related algorithms in this file were
   inspired by the 'ipaddr.py' library from Cendio Systems AB. */

#include "secnet.h"
#include <limits.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "ipaddr.h"
#include "util.h"

#define DEFAULT_ALLOC 2
#define EXTEND_ALLOC_BY 4

struct subnet_list *subnet_list_new(void)
{
    struct subnet_list *r;
    NEW(r);
    r->entries=0;
    r->alloc=DEFAULT_ALLOC;
    NEW_ARY(r->list,r->alloc);
    return r;
}

void subnet_list_free(struct subnet_list *a)
{
    if (a->list) free(a->list);
    free(a);
}

static void subnet_list_set_len(struct subnet_list *a, int32_t l)
{
    int32_t na;

    if (l>a->alloc) {
	assert(a->alloc < INT_MAX-EXTEND_ALLOC_BY);
	na=a->alloc+EXTEND_ALLOC_BY;
	REALLOC_ARY(a->list,na);
	a->alloc=na;
    }
    a->entries=l;
}

void subnet_list_append(struct subnet_list *a, uint32_t prefix, int len)
{
    struct subnet *sn;
    assert(a->entries < INT_MAX);
    subnet_list_set_len(a,a->entries+1);
    sn=&a->list[a->entries-1];
    sn->prefix=prefix;
    sn->len=len;
    sn->mask=len?(0xffffffff << (32-len)):0;
}

struct ipset *ipset_new(void)
{
    struct ipset *r;
    NEW(r);
    r->l=0;
    r->a=DEFAULT_ALLOC;
    NEW_ARY(r->d,r->a);
    return r;
}

void ipset_free(struct ipset *a)
{
    if (a->d) free(a->d);
    free(a);
}

#ifdef DEBUG
static void ipset_dump(struct ipset *a, string_t name)
{
    int32_t i;

    printf("%s: ",name);
    for (i=0; i<a->l; i++) {
	printf("[%08x-%08x] ",a->d[i].a,a->d[i].b);
    }
    printf("\n");
}
#endif

struct ipset *ipset_from_subnet(struct subnet s)
{
    struct ipset *r;

    r=ipset_new();
    r->l=1;
    r->d[0].a=s.prefix;
    r->d[0].b=s.prefix | (~s.mask);
    return r;
}

struct ipset *ipset_from_subnet_list(struct subnet_list *l)
{
    struct ipset *r, *a, *b;
    int32_t i;

    r=ipset_new();
    for (i=0; i<l->entries; i++) {
	a=ipset_from_subnet(l->list[i]);
	b=ipset_union(r,a);
	ipset_free(a);
	ipset_free(r);
	r=b;
    }
    return r;
}

static void ipset_set_len(struct ipset *a, int32_t l)
{
    int32_t na;

    if (l>a->a) {
	assert(a->a < INT_MAX-EXTEND_ALLOC_BY);
	na=a->a+EXTEND_ALLOC_BY;
	REALLOC_ARY(a->d,na);
	a->a=na;
    }
    a->l=l;
}

static void ipset_append_range(struct ipset *a, struct iprange r)
{
    ipset_set_len(a,a->l+1);
    a->d[a->l-1]=r;
}

struct ipset *ipset_union(struct ipset *a, struct ipset *b)
{
    struct ipset *c;
    struct iprange r;
    int32_t ia,ib;

    c=ipset_new();
    ia=0; ib=0;
    while (ia<a->l || ib<b->l) {
	if (ia<a->l)
	    if (ib<b->l)
		if (a->d[ia].a < b->d[ib].a)
		    r=a->d[ia++];
		else
		    r=b->d[ib++];
	    else
		r=a->d[ia++];
	else
	    r=b->d[ib++];

	if (c->l==0)
	    ipset_append_range(c,r);
	else if (r.a <= c->d[c->l-1].b+1)
	    /* Extends (or is consumed by) the last range */
	    c->d[c->l-1].b=MAX(c->d[c->l-1].b, r.b);
	else
	    ipset_append_range(c,r);
    }
    return c;
}

struct ipset *ipset_intersection(struct ipset *a, struct ipset *b)
{
    struct ipset *r;
    struct iprange ra, rb;
    int32_t ia,ib;

    r=ipset_new();
    ia=0; ib=0;

    while (ia<a->l && ib<b->l) {
	ra=a->d[ia];
	rb=b->d[ib];
	if (ra.b < rb.a)
	    /* The first entry of a doesn't overlap with any part of b */
	    ia++;
	else if (ra.a > rb.b)
	    /* The first entry of b doesn't overlap with any part of a */
	    ib++;
	else {
	    /* Trim away any leading edges */
	    if (ra.a < rb.a)
		/* a starts before b */
		ra.a=rb.a;
	    else if (ra.a > rb.a)
		/* b starts before a */
		rb.a=ra.a;

	    /* Now the ranges start at the same point */
	    if (ra.b == rb.b) {
		/* The ranges are equal */
		ipset_append_range(r,ra);
		ia++;
		ib++;
	    } else if (ra.b < rb.b) {
		/* a is the smaller range */
		ipset_append_range(r,ra);
		ia++;
	    } else {
		/* y is the smaller range */
		ipset_append_range(r,rb);
		ib++;
	    }
	}
    }
    return r;
}

struct ipset *ipset_complement(struct ipset *a)
{
    struct ipset *r;
    struct iprange n;
    int64_t pre;
    int32_t i;
    uint32_t lo,hi;

    r=ipset_new();
    pre=-1;
    for (i=0; i<a->l; i++) {
	lo=a->d[i].a;
	hi=a->d[i].b;
	if (lo!=0) {
	    n.a=pre+1;
	    n.b=lo-1;
	    ipset_append_range(r,n);
	}
	pre=hi;
    }
    if (pre!=0xffffffff) {
	n.a=pre+1;
	n.b=0xffffffff;
	ipset_append_range(r,n);
    }
    return r;
}

/* Return a-b */
struct ipset *ipset_subtract(struct ipset *a, struct ipset *b)
{
    struct ipset *c, *r;
    c=ipset_complement(b);
    r=ipset_intersection(a,c);
    ipset_free(c);
    return r;
}

bool_t ipset_is_empty(struct ipset *a)
{
   return (a->l==0);
}

bool_t ipset_contains_addr(struct ipset *a, uint32_t addr)
{
    int32_t i;
    struct iprange r;

    for (i=0; i<a->l; i++) {
	r=a->d[i];
	if (addr>=r.a && addr<=r.b) return True;
	if (addr<r.a) return False;
    }
    return False;
}

/* sub is a subset of super if it does not intersect with the complement 
   of super */
bool_t ipset_is_subset(struct ipset *super, struct ipset *sub)
{
    struct ipset *superc;
    struct ipset *inter;
    bool_t empty;

    superc=ipset_complement(super);
    inter=ipset_intersection(superc,sub);
    empty=ipset_is_empty(inter);
    ipset_free(inter);
    ipset_free(superc);
    return empty;
}

struct subnet_list *ipset_to_subnet_list(struct ipset *is)
{
    struct subnet_list *r;
    int64_t a,b,lobit,himask,lomask;
    int bits;
    int32_t i;

    r=subnet_list_new();
    for (i=0; i<is->l; i++) {
	a=is->d[i].a;
	b=is->d[i].b;

	lomask=1;
	lobit=1;
	himask=0xfffffffe;
	bits=32;
	while (a<=b) {
	    if ((a & lomask) != 0) {
		subnet_list_append(r,a,bits);
		a=a+lobit;
	    } else if ((b & lomask) != lomask) {
		subnet_list_append(r,b&himask,bits);
		b=b-lobit;
	    } else {
		lomask = (lomask << 1) | 1;
		lobit = (lobit << 1);
		himask = himask ^ lobit;
		bits = bits - 1;
		ASSERT(bits>=0);
	    }
	}
    }
    /* Sort the list? */
    return r;
}

#define IPADDR_BUFLEN 20

static char *ipaddr_getbuf(void)
{
    SBUF_DEFINE(16, IPADDR_BUFLEN);
    return SBUF;
}

/* The string buffer must be at least 16 bytes long */
string_t ipaddr_to_string(uint32_t addr)
{
    uint8_t a,b,c,d;
    string_t s;

    s=ipaddr_getbuf();
    a=addr>>24;
    b=addr>>16;
    c=addr>>8;
    d=addr;
    snprintf(s, 16, "%d.%d.%d.%d", a, b, c, d);
    return s;
}

string_t subnet_to_string(struct subnet sn)
{
    uint32_t addr=sn.prefix;
    uint8_t a,b,c,d;
    string_t s;

    s=ipaddr_getbuf();
    a=addr>>24;
    b=addr>>16;
    c=addr>>8;
    d=addr;
    snprintf(s, 19, "%d.%d.%d.%d/%d", a, b, c, d, sn.len);
    return s;
}

static struct subnet string_item_to_subnet(item_t *i, cstring_t desc,
					   bool_t *invert)
{
    struct subnet s;
    uint32_t a, b, c, d, n;
    int match;
    cstring_t in;

    *invert=False;

    /* i is not guaranteed to be a string */
    if (i->type!=t_string) {
	cfgfatal(i->loc,desc,"expecting a string (subnet specification)\n");
    }
    in=i->data.string;

    if (strcmp(in,"default")==0) {
	s.prefix=0;
	s.mask=0;
	s.len=0;
	return s;
    }

    if (*in=='!') {
	*invert=True;
	in++;
    }
    /* We expect strings of the form "a.b.c.d[/n]", i.e. the dots are
       NOT optional. The subnet mask is optional; if missing it is assumed
       to be /32. */
    match=sscanf(in,"%u.%u.%u.%u/%u", &a, &b, &c, &d, &n);
    if (match<4) {
	cfgfatal(i->loc,desc,"\"%s\" is not a valid "
		 "subnet specification\n",in);
    }
    if (match<5) {
	n=32;
    }
    if (a>255 || b>255 || c>255 || d>255 || n>32) {
	cfgfatal(i->loc,desc,"\"%s\": range error\n",in);
    }
    s.prefix=(a<<24)|(b<<16)|(c<<8)|(d);
    s.mask=n?(~0UL << (32-n)):0;
    s.len=n;
    if (s.prefix & ~s.mask) {
	cfgfatal(i->loc,desc,"\"%s\": prefix not fully contained "
		 "in mask\n",in);
    }
    return s;
}

uint32_t string_item_to_ipaddr(const item_t *i, cstring_t desc)
{
    uint32_t a, b, c, d;
    int match;

    /* i is not guaranteed to be a string */
    if (i->type!=t_string) {
	cfgfatal(i->loc,desc,"expecting a string (IP address)\n");
    }

    match=sscanf(i->data.string,"%u.%u.%u.%u", &a, &b, &c, &d);
    if (match<4) {
	cfgfatal(i->loc,desc,"\"%s\" is not a valid "
		 "IP address\n",i->data.string);
    }
    if (a>255 || b>255 || c>255 || d>255) {
	cfgfatal(i->loc,desc,"\"%s\": range error\n",i->data.string);
    }
    return (a<<24)|(b<<16)|(c<<8)|(d);
}

struct ipset *string_list_to_ipset(list_t *l, struct cloc loc,
				   cstring_t module, cstring_t param)
{
    struct ipset *r, *n, *isn;
    uint32_t e,i;
    item_t *item;
    bool_t inv;

    r=ipset_new();
    e=list_length(l);
    for (i=0; i<e; i++) {
	item=list_elem(l,i);
	isn=ipset_from_subnet(string_item_to_subnet(item,param,&inv));
	if (inv) {
	    n=ipset_subtract(r,isn);
	} else {
	    n=ipset_union(r,isn);
	}
	ipset_free(r);
	ipset_free(isn);
	r=n;
    }
    return r;
}
