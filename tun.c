#include "secnet.h"
#include "util.h"
#include "netlink.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#ifdef HAVE_LINUX_IF_H
#include <linux/if.h>
#include <linux/if_tun.h>
#endif

/* Where do we find if_tun on other platforms? */

/* Connection to the kernel through the universal TUN/TAP driver */

struct tun {
    struct netlink nl;
    int fd;
    string_t device_path;
    string_t interface_name;
    string_t ifconfig_path;
    string_t route_path;
    bool_t tun_old;
    bool_t search_for_if; /* Applies to tun-old only */
    struct buffer_if *buff; /* We receive packets into here
			       and send them to the netlink code. */
    netlink_deliver_fn *netlink_to_tunnel;
    uint32_t local_address; /* host interface address */
};

static int tun_beforepoll(void *sst, struct pollfd *fds, int *nfds_io,
			  int *timeout_io, const struct timeval *tv_now,
			  uint64_t *now)
{
    struct tun *st=sst;
    *nfds_io=1;
    fds[0].fd=st->fd;
    fds[0].events=POLLIN|POLLERR|POLLHUP;
    return 0;
}

static void tun_afterpoll(void *sst, struct pollfd *fds, int nfds,
			    const struct timeval *tv_now, uint64_t *now)
{
    struct tun *st=sst;
    int l;

    if (nfds==0) return;
    if (fds[0].revents&POLLERR) {
	printf("tun_afterpoll: hup!\n");
    }
    if (fds[0].revents&POLLIN) {
	BUF_ALLOC(st->buff,"tun_afterpoll");
	buffer_init(st->buff,st->nl.max_start_pad);
	l=read(st->fd,st->buff->start,st->buff->len-st->nl.max_start_pad);
	if (l<0) {
	    fatal_perror("tun_afterpoll: read()");
	}
	if (l==0) {
	    fatal("tun_afterpoll: read()=0; device gone away?\n");
	}
	if (l>0) {
	    st->buff->size=l;
	    st->netlink_to_tunnel(&st->nl,NULL,st->buff);
	    BUF_ASSERT_FREE(st->buff);
	}
    }
}

static void tun_deliver_to_kernel(void *sst, void *cid,
				  struct buffer_if *buf)
{
    struct tun *st=sst;

    BUF_ASSERT_USED(buf);
    /* No error checking, because we'd just throw the packet away
       anyway if it didn't work. */
    write(st->fd,buf->start,buf->size);
    BUF_FREE(buf);
}

static bool_t tun_set_route(void *sst, struct netlink_route *route)
{
    struct tun *st=sst;
    string_t network, mask, secnetaddr;

    if (route->up != route->kup) {
	network=ipaddr_to_string(route->net.prefix);
	mask=ipaddr_to_string(route->net.mask);
	secnetaddr=ipaddr_to_string(st->nl.secnet_address);
	Message(M_INFO,"%s: %s route %s/%d %s kernel routing table\n",
		st->nl.name,route->up?"adding":"deleting",network,
		route->net.len,route->up?"to":"from");
	sys_cmd(st->route_path,"route",route->up?"add":"del","-net",network,
		"netmask",mask,"gw",secnetaddr,(char *)0);
	free(network); free(mask); free(secnetaddr);
	route->kup=route->up;
	return True;
    }
    return False;
}

static void tun_phase_hook(void *sst, uint32_t newphase)
{
    struct tun *st=sst;
    string_t hostaddr,secnetaddr;
    uint8_t mtu[6];
    string_t network,mask;
    struct netlink_route *r;
    int i;

    if (st->tun_old) {
	if (st->search_for_if) {
	    string_t dname;
	    int i;

	    /* ASSERT st->interface_name */
	    dname=safe_malloc(strlen(st->device_path)+4,"tun_old_apply");
	    st->interface_name=safe_malloc(8,"tun_phase_hook");
	
	    for (i=0; i<255; i++) {
		sprintf(dname,"%s%d",st->device_path,i);
		if ((st->fd=open(dname,O_RDWR))>0) {
		    sprintf(st->interface_name,"tun%d",i);
		    Message(M_INFO,"%s: allocated network interface %s "
			    "through %s\n",st->nl.name,st->interface_name,
			    dname);
		    break;
		}
	    }
	    if (st->fd==-1) {
		fatal("%s: unable to open any TUN device (%s...)\n",
		      st->nl.name,st->device_path);
	    }
	} else {
	    st->fd=open(st->device_path,O_RDWR);
	    if (st->fd==-1) {
		fatal_perror("%s: unable to open TUN device file %s",
			     st->nl.name,st->device_path);
	    }
	}
    } else {
#ifdef HAVE_LINUX_IF_H
	struct ifreq ifr;

	/* New TUN interface: open the device, then do ioctl TUNSETIFF
	   to set or find out the network interface name. */
	st->fd=open(st->device_path,O_RDWR);
	if (st->fd==-1) {
	    fatal_perror("%s: can't open device file %s",st->nl.name,
			 st->device_path);
	}
	memset(&ifr,0,sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI; /* Just send/receive IP packets,
						no extra headers */
	if (st->interface_name)
	    strncpy(ifr.ifr_name,st->interface_name,IFNAMSIZ);
	Message(M_DEBUG,"%s: about to ioctl(TUNSETIFF)...\n",st->nl.name);
	if (ioctl(st->fd,TUNSETIFF,&ifr)<0) {
	    fatal_perror("%s: ioctl(TUNSETIFF)",st->nl.name);
	}
	if (!st->interface_name) {
	    st->interface_name=safe_malloc(strlen(ifr.ifr_name)+1,"tun_apply");
	    strcpy(st->interface_name,ifr.ifr_name);
	    Message(M_INFO,"%s: allocated network interface %s\n",st->nl.name,
		    st->interface_name);
	}
#else
	fatal("netlink.c:tun_phase_hook:!tun_old unexpected\n");
#endif /* HAVE_LINUX_IF_H */
    }
    /* All the networks we'll be using have been registered. Invoke ifconfig
       to set the TUN device's address, and route to add routes to all
       our networks. */

    hostaddr=ipaddr_to_string(st->local_address);
    secnetaddr=ipaddr_to_string(st->nl.secnet_address);
    snprintf(mtu,6,"%d",st->nl.mtu);
    mtu[5]=0;

    sys_cmd(st->ifconfig_path,"ifconfig",st->interface_name,
	    hostaddr,"netmask","255.255.255.255","-broadcast",
	    "pointopoint",secnetaddr,"mtu",mtu,"up",(char *)0);

    r=st->nl.routes;
    for (i=0; i<st->nl.n_routes; i++) {
	if (r[i].up && !r[i].kup) {
	    network=ipaddr_to_string(r[i].net.prefix);
	    mask=ipaddr_to_string(r[i].net.mask);
	    sys_cmd(st->route_path,"route","add","-net",network,
		    "netmask",mask,"gw",secnetaddr,(char *)0);
	    r[i].kup=True;
	}
    }

    /* Register for poll() */
    register_for_poll(st, tun_beforepoll, tun_afterpoll, 1, st->nl.name);
}

#ifdef HAVE_LINUX_IF_H
static list_t *tun_apply(closure_t *self, struct cloc loc, dict_t *context,
			 list_t *args)
{
    struct tun *st;
    item_t *item;
    dict_t *dict;

    st=safe_malloc(sizeof(*st),"tun_apply");

    /* First parameter must be a dict */
    item=list_elem(args,0);
    if (!item || item->type!=t_dict)
	cfgfatal(loc,"tun","parameter must be a dictionary\n");
    
    dict=item->data.dict;

    st->netlink_to_tunnel=
	netlink_init(&st->nl,st,loc,dict,
		     "netlink-tun",tun_set_route,tun_deliver_to_kernel);

    st->tun_old=False;
    st->device_path=dict_read_string(dict,"device",False,"tun-netlink",loc);
    st->interface_name=dict_read_string(dict,"interface",False,
					"tun-netlink",loc);
    st->ifconfig_path=dict_read_string(dict,"ifconfig-path",
				       False,"tun-netlink",loc);
    st->route_path=dict_read_string(dict,"route-path",
				    False,"tun-netlink",loc);

    if (!st->device_path) st->device_path="/dev/net/tun";
    if (!st->ifconfig_path) st->ifconfig_path="ifconfig";
    if (!st->route_path) st->route_path="route";
    st->buff=find_cl_if(dict,"buffer",CL_BUFFER,True,"tun-netlink",loc);
    st->local_address=string_to_ipaddr(
	dict_find_item(dict,"local-address", True, "netlink", loc),"netlink");

    add_hook(PHASE_GETRESOURCES,tun_phase_hook,st);

    return new_closure(&st->nl.cl);
}
#endif /* HAVE_LINUX_IF_H */

static list_t *tun_old_apply(closure_t *self, struct cloc loc, dict_t *context,
			     list_t *args)
{
    struct tun *st;
    item_t *item;
    dict_t *dict;

    st=safe_malloc(sizeof(*st),"tun_old_apply");

    /* First parameter must be a dict */
    item=list_elem(args,0);
    if (!item || item->type!=t_dict)
	cfgfatal(loc,"tun","parameter must be a dictionary\n");
    
    dict=item->data.dict;

    st->netlink_to_tunnel=
	netlink_init(&st->nl,st,loc,dict,
		     "netlink-tun",NULL,tun_deliver_to_kernel);

    st->tun_old=True;
    st->device_path=dict_read_string(dict,"device",False,"tun-netlink",loc);
    st->interface_name=dict_read_string(dict,"interface",False,
					"tun-netlink",loc);
    st->search_for_if=dict_read_bool(dict,"interface-search",False,
				     "tun-netlink",loc,st->device_path==NULL);
    st->ifconfig_path=dict_read_string(dict,"ifconfig-path",False,
				       "tun-netlink",loc);
    st->route_path=dict_read_string(dict,"route-path",False,"tun-netlink",loc);

    if (!st->device_path) st->device_path="/dev/tun";
    if (!st->ifconfig_path) st->ifconfig_path="ifconfig";
    if (!st->route_path) st->route_path="route";
    st->buff=find_cl_if(dict,"buffer",CL_BUFFER,True,"tun-netlink",loc);
    st->local_address=string_to_ipaddr(
	dict_find_item(dict,"local-address", True, "netlink", loc),"netlink");

    /* Old TUN interface: the network interface name depends on which
       /dev/tunX file we open. If 'interface-search' is set to true, treat
       'device' as the prefix and try numbers from 0--255. If it's set
       to false, treat 'device' as the whole name, and require than an
       appropriate interface name be specified. */
    if (st->search_for_if && st->interface_name) {
	cfgfatal(loc,"tun-old","you may not specify an interface name "
		 "in interface-search mode\n");
    }
    if (!st->search_for_if && !st->interface_name) {
	cfgfatal(loc,"tun-old","you must specify an interface name "
		 "when you explicitly specify a TUN device file\n");
    }


    add_hook(PHASE_GETRESOURCES,tun_phase_hook,st);

    return new_closure(&st->nl.cl);
}

init_module tun_module;
void tun_module(dict_t *dict)
{
#ifdef HAVE_LINUX_IF_H
    add_closure(dict,"tun",tun_apply);
#endif
    add_closure(dict,"tun-old",tun_old_apply);
}
