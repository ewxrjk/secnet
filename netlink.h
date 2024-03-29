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
    int32_t mtu;
    uint32_t options;
    uint32_t outcount;
    bool_t up; /* Should these routes exist in the kernel? */
    bool_t kup; /* Do these routes exist in the kernel? */
    struct netlink_client *next;
};

/* options field in 'struct netlink_client' */
#define OPT_SOFTROUTE   1
#define OPT_ALLOWROUTE  2

typedef bool_t netlink_route_fn(void *cst, struct netlink_client *routes);

/* Netlink provides one function to the device driver, to call to deliver
   a packet from the device. The device driver provides one function to
   netlink, for it to call to deliver a packet to the device. */

struct netlink {
    closure_t cl;
    void *dst; /* Pointer to host interface state */
    cstring_t name;
    struct ipset *networks; /* Local networks */
    struct subnet_list *subnets; /* Same as networks, for display */
    struct ipset *remote_networks; /* Allowable remote networks */
    uint32_t local_address; /* host interface address */
    uint32_t secnet_address; /* our own address, or the address of the
				other end of a point-to-point link */
    bool_t ptp;
    int32_t mtu;
    struct netlink_client *clients; /* Linked list of clients */
    struct netlink_client **routes; /* Array of clients, sorted by priority */
    int32_t n_clients;
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
