#include "secnet.h"
#include <stdio.h>

/* This file should eventually incorporate all the functionality of
   ipaddr.py */

bool_t subnet_match(struct subnet *s, uint32_t address)
{
    return (s->prefix==(address&s->mask));
}

bool_t subnet_matches_list(struct subnet_list *list, uint32_t address)
{
    uint32_t i;
    for (i=0; i<list->entries; i++) {
	if (list->list[i].prefix == (address&list->list[i].mask)) return True;
    }
    return False;
}

bool_t subnets_intersect(struct subnet a, struct subnet b)
{
    uint32_t mask=a.mask&b.mask;
    return ((a.prefix&mask)==(b.prefix&mask));
}

bool_t subnet_intersects_with_list(struct subnet a, struct subnet_list *b)
{
    uint32_t i;

    for (i=0; i<b->entries; i++) {
	if (subnets_intersect(a,b->list[i])) return True;
    }
    return False;
}

bool_t subnet_lists_intersect(struct subnet_list *a, struct subnet_list *b)
{
    uint32_t i;
    for (i=0; i<a->entries; i++) {
	if (subnet_intersects_with_list(a->list[i],b)) return True;
    }
    return False;
}

/* The string buffer must be at least 16 bytes long */
string_t ipaddr_to_string(uint32_t addr)
{
    uint8_t a,b,c,d;
    string_t s;

    s=safe_malloc(16,"ipaddr_to_string");
    a=addr>>24;
    b=addr>>16;
    c=addr>>8;
    d=addr;
    snprintf(s, 16, "%d.%d.%d.%d", a, b, c, d);
    return s;
}

string_t subnet_to_string(struct subnet *sn)
{
    uint32_t mask=sn->mask, addr=sn->prefix;
    uint8_t a,b,c,d;
    string_t s;
    int i;

    s=safe_malloc(19,"subnet_to_string");
    a=addr>>24;
    b=addr>>16;
    c=addr>>8;
    d=addr;
    for (i=0; mask; i++) {
	mask=(mask<<1);
    }
    if (i!=sn->len) {
	fatal("subnet_to_string: invalid subnet structure "
	      "(i=%d sn->len=%d mask=0x%08x)!\n",i,sn->len,sn->mask);
    }
    snprintf(s, 19, "%d.%d.%d.%d/%d", a, b, c, d, sn->len);
    return s;
}
