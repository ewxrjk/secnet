#ifndef netlink_h
#define netlink_h

#define DEFAULT_BUFSIZE 2048
#define DEFAULT_MTU 1000
#define ICMP_BUFSIZE 1024

struct netlink_client {
    struct subnet_list *networks;
    netlink_deliver_fn *deliver;
    void *dst;
    string_t name;
    uint32_t link_quality;
    uint32_t options;
    struct netlink_client *next;
};

struct netlink_route {
    struct subnet net;
    bool_t hard;
    bool_t allow_route;
    bool_t up;
    bool_t kup;
    struct netlink_client *c;
};

typedef bool_t netlink_route_fn(void *cst, struct netlink_route *route);

/* Netlink provides one function to the device driver, to call to deliver
   a packet from the device. The device driver provides one function to
   netlink, for it to call to deliver a packet to the device. */

struct netlink {
    closure_t cl;
    struct netlink_if ops;
    void *dst; /* Pointer to host interface state */
    string_t name;
    uint32_t max_start_pad;
    uint32_t max_end_pad;
    struct subnet_list networks;
    struct subnet_list exclude_remote_networks;
    uint32_t local_address; /* host interface address */
    uint32_t secnet_address; /* our own address */
    uint32_t mtu;
    struct netlink_client *clients;
    netlink_deliver_fn *deliver_to_host; /* Provided by driver */
    netlink_route_fn *set_route; /* Provided by driver */
    struct buffer_if icmp; /* Buffer for assembly of outgoing ICMP */
    uint32_t n_routes; /* How many routes do we know about? */
    struct netlink_route *routes;
};

extern netlink_deliver_fn *netlink_init(struct netlink *st,
					void *dst, struct cloc loc,
					dict_t *dict, string_t description,
					netlink_route_fn *set_route,
					netlink_deliver_fn *to_host);

#endif /* netlink_h */
