#ifndef ipaddr_h
#define ipaddr_h

/* Match an address (in HOST byte order) with a subnet list.
   Returns True if matched. */
extern bool_t subnet_match(struct subnet *s, uint32_t address);
extern bool_t subnet_matches_list(struct subnet_list *list, uint32_t address);
extern bool_t subnets_intersect(struct subnet a, struct subnet b);
extern bool_t subnet_intersects_with_list(struct subnet a,
					  struct subnet_list *b);
extern bool_t subnet_lists_intersect(struct subnet_list *a,
				     struct subnet_list *b);


extern string_t ipaddr_to_string(uint32_t addr);
extern string_t subnet_to_string(struct subnet *sn);

#endif /* ipaddr_h */
