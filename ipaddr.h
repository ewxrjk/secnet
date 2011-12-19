/* Useful functions for dealing with collections of IP addresses */

#ifndef ipaddr_h
#define ipaddr_h

struct subnet {
    uint32_t prefix;
    uint32_t mask;
    int len;
};

struct subnet_list {
    int32_t entries;
    int32_t alloc;
    struct subnet *list;
};

struct iprange {
    uint32_t a,b;
};

struct ipset {
    int32_t l; /* Number of entries in list */
    int32_t a; /* Allocated space in list */
    struct iprange *d;
};

extern struct subnet_list *subnet_list_new(void);
extern void subnet_list_free(struct subnet_list *a);
extern void subnet_list_append(struct subnet_list *a, uint32_t prefix, int len);

static inline bool_t subnet_match(struct subnet s, uint32_t address)
{
    return (s.prefix==(address&s.mask));
}

extern struct ipset *ipset_new(void);
extern void ipset_free(struct ipset *a);
extern struct ipset *ipset_from_subnet(struct subnet s);
extern struct ipset *ipset_from_subnet_list(struct subnet_list *l);
extern struct ipset *ipset_union(struct ipset *a, struct ipset *b);
extern struct ipset *ipset_intersection(struct ipset *a, struct ipset *b);
extern struct ipset *ipset_complement(struct ipset *a);
extern struct ipset *ipset_subtract(struct ipset *a, struct ipset *b);
extern bool_t ipset_is_empty(struct ipset *a);
extern bool_t ipset_contains_addr(struct ipset *a, uint32_t addr);
extern bool_t ipset_is_subset(struct ipset *super, struct ipset *sub);
extern struct subnet_list *ipset_to_subnet_list(struct ipset *is);

extern char *ipaddr_to_string(uint32_t addr);
extern char *subnet_to_string(struct subnet sn);

extern struct ipset *string_list_to_ipset(list_t *l,struct cloc loc,
					  const char *module,
					  const char *param);
					  
extern uint32_t string_item_to_ipaddr(item_t *i, const char *desc);

#endif /* ipaddr_h */
