#ifndef netlink_h
#define netlink_h

#include "ipaddr.h"

#define DEFAULT_BUFSIZE 2048
#define DEFAULT_MTU 1000
#define ICMP_BUFSIZE 1024

struct netlink;

struct netlink_client {
    closure_t cl;
    struct netlink_if ops;
    struct netlink *nst;
    struct ipset *networks;
    struct subnet_list *subnets; /* Same information as 'networks' */
    uint32_t priority; /* Higher priority clients have their networks
			  checked first during routing.  This allows
			  things like laptops to supersede whole
			  networks. */
    netlink_deliver_fn *deliver;
    void *dst;
    string_t name;
    uint32_t link_quality;
    uint32_t mtu;
    uint32_t options;
    uint32_t outcount;
    bool_t up; /* Should these routes exist in the kernel? */
    bool_t kup; /* Do these routes exist in the kernel? */
    struct netlink_client *next;
};

typedef bool_t netlink_route_fn(void *cst, struct netlink_client *routes);

/* Netlink provides one function to the device driver, to call to deliver
   a packet from the device. The device driver provides one function to
   netlink, for it to call to deliver a packet to the device. */

struct netlink {
    closure_t cl;
    void *dst; /* Pointer to host interface state */
    cstring_t name;
    uint32_t max_start_pad;
    uint32_t max_end_pad;
    struct ipset *networks; /* Local networks */
    struct subnet_list *subnets; /* Same as networks, for display */
    struct ipset *remote_networks; /* Allowable remote networks */
    uint32_t secnet_address; /* our own address, or the address of the
				other end of a point-to-point link */
    bool_t ptp;
    uint32_t mtu;
    struct netlink_client *clients; /* Linked list of clients */
    struct netlink_client **routes; /* Array of clients, sorted by priority */
    uint32_t n_clients;
    netlink_deliver_fn *deliver_to_host; /* Provided by driver */
    netlink_route_fn *set_routes; /* Provided by driver */
    struct buffer_if icmp; /* Buffer for assembly of outgoing ICMP */
    uint32_t outcount; /* Packets sent to host */
    uint32_t localcount; /* Packets sent to secnet */
};

extern netlink_deliver_fn *netlink_init(struct netlink *st,
					void *dst, struct cloc loc,
					dict_t *dict, cstring_t description,
					netlink_route_fn *set_routes,
					netlink_deliver_fn *to_host);

#endif /* netlink_h */
