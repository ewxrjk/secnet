#include "secnet.h"
#include "util.h"
#include "netlink.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/socket.h>

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#ifdef HAVE_LINUX_IF_H
#include <linux/if_tun.h>
#define LINUX_TUN_SUPPORTED
#endif
#endif

#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif

#if defined(HAVE_STROPTS_H) && defined(HAVE_SYS_SOCKIO_H) && \
defined(HAVE_NET_IF_TUN_H)
#define HAVE_TUN_STREAMS
#endif

#ifdef HAVE_TUN_STREAMS
#include <stropts.h>
#include <sys/sockio.h>
#include <net/if_tun.h>
#endif

#define TUN_FLAVOUR_GUESS   0
#define TUN_FLAVOUR_BSD     1
#define TUN_FLAVOUR_LINUX   2
#define TUN_FLAVOUR_STREAMS 3

static struct flagstr flavours[]={
    {"guess", TUN_FLAVOUR_GUESS},
    {"bsd", TUN_FLAVOUR_BSD},
    {"BSD", TUN_FLAVOUR_BSD},
    {"linux", TUN_FLAVOUR_LINUX},
    {"streams", TUN_FLAVOUR_STREAMS},
    {"STREAMS", TUN_FLAVOUR_STREAMS},
    {NULL, 0}
};

#define TUN_CONFIG_GUESS      0
#define TUN_CONFIG_IOCTL      1
#define TUN_CONFIG_BSD        2
#define TUN_CONFIG_LINUX      3
#define TUN_CONFIG_SOLARIS25  4

static struct flagstr config_types[]={
    {"guess", TUN_CONFIG_GUESS},
    {"ioctl", TUN_CONFIG_IOCTL},
    {"bsd", TUN_CONFIG_BSD},
    {"BSD", TUN_CONFIG_BSD},
    {"linux", TUN_CONFIG_LINUX},
    {"solaris-2.5", TUN_CONFIG_SOLARIS25},
    {NULL, 0}
};

/* Connection to the kernel through the universal TUN/TAP driver */

struct tun {
    struct netlink nl;
    int fd;
    const char *device_path;
    const char *ip_path;
    char *interface_name;
    const char *ifconfig_path;
    uint32_t ifconfig_type;
    const char *route_path;
    uint32_t route_type;
    uint32_t tun_flavour;
    bool_t search_for_if; /* Applies to tun-BSD only */
    struct buffer_if *buff; /* We receive packets into here
			       and send them to the netlink code. */
    netlink_deliver_fn *netlink_to_tunnel;
    uint32_t local_address; /* host interface address */
};

static const char *tun_flavour_str(uint32_t flavour)
{
    switch (flavour) {
    case TUN_FLAVOUR_GUESS: return "guess";
    case TUN_FLAVOUR_BSD: return "BSD";
    case TUN_FLAVOUR_LINUX: return "linux";
    case TUN_FLAVOUR_STREAMS: return "STREAMS";
    default: return "unknown";
    }
}

static int tun_beforepoll(void *sst, struct pollfd *fds, int *nfds_io,
			  int *timeout_io)
{
    struct tun *st=sst;
    *nfds_io=1;
    fds[0].fd=st->fd;
    fds[0].events=POLLIN;
    return 0;
}

static void tun_afterpoll(void *sst, struct pollfd *fds, int nfds)
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
	    fatal("tun_afterpoll: read()=0; device gone away?");
	}
	if (l>0) {
	    st->buff->size=l;
	    st->netlink_to_tunnel(&st->nl,st->buff);
	    BUF_ASSERT_FREE(st->buff);
	}
    }
}

static void tun_deliver_to_kernel(void *sst, struct buffer_if *buf)
{
    struct tun *st=sst;
    ssize_t rc;

    BUF_ASSERT_USED(buf);
    
    /* Log errors, so we can tell what's going on, but only once a
       minute, so we don't flood the logs.  Short writes count as
       errors. */
    rc = write(st->fd,buf->start,buf->size);
    if(rc != buf->size) {
	static struct timeval last_report;
	if(tv_now_global.tv_sec >= last_report.tv_sec + 60) {
	    if(rc < 0)
		Message(M_WARNING,
			"failed to deliver packet to tun device: %s\n",
			strerror(errno));
	    else
		Message(M_WARNING,
			"truncated packet delivered to tun device\n");
	    last_report = tv_now_global;
	}
    }
    BUF_FREE(buf);
}

static bool_t tun_set_route(void *sst, struct netlink_client *routes)
{
    struct tun *st=sst;
    char *network, *mask, *secnetaddr;
    struct subnet_list *nets;
    int32_t i;
    int fd=-1;

    if (routes->up == routes->kup) return False;
    if (st->route_type==TUN_CONFIG_IOCTL) {
	if (st->tun_flavour==TUN_FLAVOUR_STREAMS) {
	    fd=open(st->ip_path,O_RDWR);
	    if (fd<0) {
		fatal_perror("tun_set_route: can't open %s",st->ip_path);
	    }
	} else {
	    fd=socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	    if (fd<0) {
		fatal_perror("tun_set_route: socket()");
	    }
	}
    }
    nets=routes->subnets;
    secnetaddr=ipaddr_to_string(st->nl.secnet_address);
    for (i=0; i<nets->entries; i++) {
	network=ipaddr_to_string(nets->list[i].prefix);
	mask=ipaddr_to_string(nets->list[i].mask);
	Message(M_INFO,"%s: %s route %s/%d %s kernel routing table\n",
		st->nl.name,routes->up?"adding":"deleting",network,
		nets->list[i].len,routes->up?"to":"from");
	switch (st->route_type) {
	case TUN_CONFIG_LINUX:
	    sys_cmd(st->route_path,"route",routes->up?"add":"del",
		    "-net",network,"netmask",mask,
		    "gw",secnetaddr,(char *)0);
	    break;
	case TUN_CONFIG_BSD:
	    sys_cmd(st->route_path,"route",routes->up?"add":"del",
		    "-net",network,secnetaddr,mask,(char *)0);
	    break;
	case TUN_CONFIG_SOLARIS25:
	    sys_cmd(st->route_path,"route",routes->up?"add":"del",
		    network,secnetaddr,(char *)0);
	    break;
	case TUN_CONFIG_IOCTL:
	{
	  /* darwin rtentry has a different format, use /sbin/route instead */
#if HAVE_NET_ROUTE_H && ! __APPLE__
	    struct rtentry rt;
	    struct sockaddr_in *sa;
	    int action;
	    
	    FILLZERO(rt);
	    sa=(struct sockaddr_in *)&rt.rt_dst;
	    sa->sin_family=AF_INET;
	    sa->sin_addr.s_addr=htonl(nets->list[i].prefix);
	    sa=(struct sockaddr_in *)&rt.rt_genmask;
	    sa->sin_family=AF_INET;
	    sa->sin_addr.s_addr=htonl(nets->list[i].mask);
	    sa=(struct sockaddr_in *)&rt.rt_gateway;
	    sa->sin_family=AF_INET;
	    sa->sin_addr.s_addr=htonl(st->nl.secnet_address);
	    rt.rt_flags=RTF_UP|RTF_GATEWAY;
	    action=routes->up?SIOCADDRT:SIOCDELRT;
	    if (ioctl(fd,action,&rt)<0) {
		fatal_perror("tun_set_route: ioctl()");
	    }
#else
	    fatal("tun_set_route: ioctl method not supported");
#endif
	}
	break;
	default:
	    fatal("tun_set_route: unsupported route command type");
	    break;
	}
	free(network); free(mask);
    }
    free(secnetaddr);
    if (st->route_type==TUN_CONFIG_IOCTL) {
	close(fd);
    }
    routes->kup=routes->up;
    return True;
}

static void tun_phase_hook(void *sst, uint32_t newphase)
{
    struct tun *st=sst;
    char *hostaddr,*secnetaddr;
    char mtu[6];
    struct netlink_client *r;

    if (st->tun_flavour==TUN_FLAVOUR_BSD) {
	if (st->search_for_if) {
	    int i;
	
	    for (i=0; i<255; i++) {
		char *dname = safe_asprintf("%s%d",st->device_path,i);
		if ((st->fd=open(dname,O_RDWR))>0) {
		    st->interface_name = safe_asprintf("tun%d",i);
		    Message(M_INFO,"%s: allocated network interface %s "
			    "through %s\n",st->nl.name,st->interface_name,
			    dname);
		    break;
		}
	    }
	    if (st->fd==-1) {
		fatal("%s: unable to open any TUN device (%s...)",
		      st->nl.name,st->device_path);
	    }
	} else {
	    st->fd=open(st->device_path,O_RDWR);
	    if (st->fd==-1) {
		fatal_perror("%s: unable to open TUN device file %s",
			     st->nl.name,st->device_path);
	    }
	}
    } else if (st->tun_flavour==TUN_FLAVOUR_LINUX) {
#ifdef LINUX_TUN_SUPPORTED
	struct ifreq ifr;

	/* New TUN interface: open the device, then do ioctl TUNSETIFF
	   to set or find out the network interface name. */
	st->fd=open(st->device_path,O_RDWR);
	if (st->fd==-1) {
	    fatal_perror("%s: can't open device file %s",st->nl.name,
			 st->device_path);
	}
	FILLZERO(ifr);
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI; /* Just send/receive IP packets,
						no extra headers */
	if (st->interface_name)
	    strncpy(ifr.ifr_name,st->interface_name,IFNAMSIZ);
	if (ioctl(st->fd,TUNSETIFF,&ifr)<0) {
	    fatal_perror("%s: ioctl(TUNSETIFF)",st->nl.name);
	}
	if (!st->interface_name) {
	    st->interface_name=safe_strdup(ifr.ifr_name,"tun_apply");
	    Message(M_INFO,"%s: allocated network interface %s\n",st->nl.name,
		    st->interface_name);
	}
#else
	fatal("tun_phase_hook: TUN_FLAVOUR_LINUX unexpected");
#endif /* LINUX_TUN_SUPPORTED */
    } else if (st->tun_flavour==TUN_FLAVOUR_STREAMS) {
#ifdef HAVE_TUN_STREAMS
	int tun_fd, if_fd, ppa=-1, ip_fd;

	if ((ip_fd=open(st->ip_path, O_RDWR)) < 0) {
	    fatal_perror("%s: can't open %s",st->nl.name,st->ip_path);
	}
	if ((tun_fd=open(st->device_path,O_RDWR)) < 0) {
	    fatal_perror("%s: can't open %s",st->nl.name,st->device_path);
	}
	if ((ppa=ioctl(tun_fd,TUNNEWPPA,ppa)) < 0) {
	    fatal_perror("%s: can't assign new interface");
	}
	if ((if_fd=open(st->device_path,O_RDWR)) < 0) {
	    fatal_perror("%s: can't open %s (2)",st->nl.name,st->device_path);
	}
	if (ioctl(if_fd,I_PUSH,"ip") < 0) {
	    fatal_perror("%s: can't push IP module",st->nl.name);
	}
	if (ioctl(if_fd,IF_UNITSEL,(char *)&ppa) < 0) {
	    fatal_perror("%s: can't set ppa %d",st->nl.name,ppa);
	}
	if (ioctl(ip_fd, I_LINK, if_fd) < 0) {
	    fatal_perror("%s: can't link TUN device to IP",st->nl.name);
	}
	st->interface_name=safe_asprintf("tun%d",ppa);
	st->fd=tun_fd;
#else
	fatal("tun_phase_hook: TUN_FLAVOUR_STREAMS unexpected");
#endif /* HAVE_TUN_STREAMS */
    } else {
	fatal("tun_phase_hook: unknown flavour of TUN");
    }
    /* All the networks we'll be using have been registered. Invoke ifconfig
       to set the TUN device's address, and route to add routes to all
       our networks. */

    hostaddr=ipaddr_to_string(st->local_address);
    secnetaddr=ipaddr_to_string(st->nl.secnet_address);
    snprintf(mtu,sizeof(mtu),"%d",st->nl.mtu);
    mtu[5]=0;

    switch (st->ifconfig_type) {
    case TUN_CONFIG_LINUX:
	sys_cmd(st->ifconfig_path,"ifconfig",st->interface_name,
		hostaddr,"netmask","255.255.255.255","-broadcast",
		"-multicast",
		"pointopoint",secnetaddr,"mtu",mtu,"up",(char *)0);
	break;
    case TUN_CONFIG_BSD:
	sys_cmd(st->ifconfig_path,"ifconfig",st->interface_name,
		hostaddr,"netmask","255.255.255.255",
		secnetaddr,"mtu",mtu,"up",(char *)0);
	break;
    case TUN_CONFIG_SOLARIS25:
	sys_cmd(st->ifconfig_path,"ifconfig",st->interface_name,
		hostaddr,secnetaddr,"mtu",mtu,"up",(char *)0);
	break;
    case TUN_CONFIG_IOCTL:
#if HAVE_NET_IF_H && ! __APPLE__
    {
	int fd;
	struct ifreq ifr;
	struct sockaddr_in *sa;
	fd=socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	/* Interface address */
	strncpy(ifr.ifr_name,st->interface_name,IFNAMSIZ);
	sa=(struct sockaddr_in *)&ifr.ifr_addr;
	FILLZERO(*sa);
	sa->sin_family=AF_INET;
	sa->sin_addr.s_addr=htonl(st->local_address);
	if (ioctl(fd,SIOCSIFADDR, &ifr)!=0) {
	    fatal_perror("tun_apply: SIOCSIFADDR");
	}
#ifdef SIOCSIFNETMASK
	/* Netmask */
	strncpy(ifr.ifr_name,st->interface_name,IFNAMSIZ);
	sa=(struct sockaddr_in *)&ifr.ifr_netmask;
	FILLZERO(*sa);
	sa->sin_family=AF_INET;
	sa->sin_addr.s_addr=htonl(0xffffffff);
	if (ioctl(fd,SIOCSIFNETMASK, &ifr)!=0) {
	    fatal_perror("tun_apply: SIOCSIFNETMASK");
	}
#endif
	/* Destination address (point-to-point) */
	strncpy(ifr.ifr_name,st->interface_name,IFNAMSIZ);
	sa=(struct sockaddr_in *)&ifr.ifr_dstaddr;
	FILLZERO(*sa);
	sa->sin_family=AF_INET;
	sa->sin_addr.s_addr=htonl(st->nl.secnet_address);
	if (ioctl(fd,SIOCSIFDSTADDR, &ifr)!=0) {
	    fatal_perror("tun_apply: SIOCSIFDSTADDR");
	}
	/* MTU */
	strncpy(ifr.ifr_name,st->interface_name,IFNAMSIZ);
	ifr.ifr_mtu=st->nl.mtu;
	if (ioctl(fd,SIOCSIFMTU, &ifr)!=0) {
	    fatal_perror("tun_apply: SIOCSIFMTU");
	}
	/* Flags */
	strncpy(ifr.ifr_name,st->interface_name,IFNAMSIZ);
	ifr.ifr_flags=IFF_UP|IFF_POINTOPOINT|IFF_RUNNING|IFF_NOARP;
	if (ioctl(fd,SIOCSIFFLAGS, &ifr)!=0) {
	    fatal_perror("tun_apply: SIOCSIFFLAGS");
	}

	close(fd);
    }
#else
    fatal("tun_apply: ifconfig by ioctl() not supported");
#endif /* HAVE_NET_IF_H */
    break;
    default:
	fatal("tun_apply: unsupported ifconfig method");
	break;
    }
	
    for (r=st->nl.clients; r; r=r->next) {
	tun_set_route(st,r);
    }

    /* Register for poll() */
    register_for_poll(st, tun_beforepoll, tun_afterpoll, 1, st->nl.name);

    free(hostaddr);
    free(secnetaddr);
}

static list_t *tun_create(closure_t *self, struct cloc loc, dict_t *context,
			  list_t *args,uint32_t default_flavour)
{
    struct tun *st;
    item_t *item;
    dict_t *dict;
    char *flavour,*type;

    NEW(st,"tun_apply");

    /* First parameter must be a dict */
    item=list_elem(args,0);
    if (!item || item->type!=t_dict)
	cfgfatal(loc,"tun","parameter must be a dictionary\n");
    
    dict=item->data.dict;

    st->netlink_to_tunnel=
	netlink_init(&st->nl,st,loc,dict,
		     "netlink-tun",tun_set_route,tun_deliver_to_kernel);

    flavour=dict_read_string(dict,"flavour",False,"tun-netlink",loc);
    if (flavour)
	st->tun_flavour=string_to_word(flavour,loc,flavours,"tun-flavour");
    else
	st->tun_flavour=default_flavour;

    st->device_path=dict_read_string(dict,"device",False,"tun-netlink",loc);
    st->ip_path=dict_read_string(dict,"ip-path",False,"tun-netlink",loc);
    st->interface_name=dict_read_string(dict,"interface",False,
					"tun-netlink",loc);
    st->search_for_if=dict_read_bool(dict,"interface-search",False,
				     "tun-netlink",loc,st->device_path==NULL);

    type=dict_read_string(dict,"ifconfig-type",False,"tun-netlink",loc);
    if (type) st->ifconfig_type=string_to_word(type,loc,config_types,
					       "ifconfig-type");
    else st->ifconfig_type=TUN_CONFIG_GUESS;
    st->ifconfig_path=dict_read_string(dict,"ifconfig-path",False,
				       "tun-netlink",loc);

    type=dict_read_string(dict,"route-type",False,"tun-netlink",loc);
    if (type) st->route_type=string_to_word(type,loc,config_types,
					    "route-type");
    else st->route_type=TUN_CONFIG_GUESS;
    st->route_path=dict_read_string(dict,"route-path",False,"tun-netlink",loc);

    st->buff=find_cl_if(dict,"buffer",CL_BUFFER,True,"tun-netlink",loc);
    st->local_address=string_item_to_ipaddr(
	dict_find_item(dict,"local-address", True, "netlink", loc),"netlink");

    if (st->tun_flavour==TUN_FLAVOUR_GUESS) {
	/* If we haven't been told what type of TUN we're using, take
	   a guess based on the system details. */
	struct utsname u;
	if (uname(&u)<0) {
	    fatal_perror("tun_create: uname");
	}
	if (strcmp(u.sysname,"Linux")==0) {
	    st->tun_flavour=TUN_FLAVOUR_LINUX;
	} else if (strcmp(u.sysname,"SunOS")==0) {
	    st->tun_flavour=TUN_FLAVOUR_STREAMS;
	} else if (strcmp(u.sysname,"FreeBSD")==0
		   || strcmp(u.sysname,"Darwin")==0) {
	    st->tun_flavour=TUN_FLAVOUR_BSD;
	}
    }
    if (st->tun_flavour==TUN_FLAVOUR_GUESS) {
	cfgfatal(loc,"tun","cannot guess which type of TUN is in use; "
		 "specify the flavour explicitly\n");
    }

    if (st->ifconfig_type==TUN_CONFIG_GUESS) {
	switch (st->tun_flavour) {
	case TUN_FLAVOUR_LINUX:
	    st->ifconfig_type=TUN_CONFIG_IOCTL;
	    break;
	case TUN_FLAVOUR_BSD:
#if __linux__
	    /* XXX on Linux we still want TUN_CONFIG_IOCTL.  Perhaps we can
	       use this on BSD too. */
	    st->ifconfig_type=TUN_CONFIG_IOCTL;
#else	  
	    st->ifconfig_type=TUN_CONFIG_BSD;
#endif
	    break;
	case TUN_FLAVOUR_STREAMS:
	    st->ifconfig_type=TUN_CONFIG_BSD;
	    break;
	}
    }
    if (st->route_type==TUN_CONFIG_GUESS)
	st->route_type=st->ifconfig_type;

    if (st->ifconfig_type==TUN_CONFIG_GUESS) {
	cfgfatal(loc,"tun","cannot guess which ifconfig method to use\n");
    }
    if (st->route_type==TUN_CONFIG_GUESS) {
	cfgfatal(loc,"tun","cannot guess which route method to use\n");
    }

    if (st->ifconfig_type==TUN_CONFIG_IOCTL && st->ifconfig_path) {
	cfgfatal(loc,"tun","ifconfig-type \"ioctl\" is incompatible with "
		 "ifconfig-path\n");
    }
    if (st->route_type==TUN_CONFIG_IOCTL && st->route_path) {
	cfgfatal(loc,"tun","route-type \"ioctl\" is incompatible with "
		 "route-path\n");
    }

    Message(M_DEBUG_CONFIG,"%s: tun flavour %s\n",st->nl.name,
	    tun_flavour_str(st->tun_flavour));
    switch (st->tun_flavour) {
    case TUN_FLAVOUR_BSD:
	if (!st->device_path) st->device_path="/dev/tun";
	break;
    case TUN_FLAVOUR_LINUX:
	if (!st->device_path) st->device_path="/dev/net/tun";
	break;
    case TUN_FLAVOUR_STREAMS:
	if (!st->device_path) st->device_path="/dev/tun";
	if (st->interface_name) cfgfatal(loc,"tun","interface name cannot "
					 "be specified with STREAMS TUN\n");
	break;
    }
    
    if (!st->ip_path) st->ip_path="/dev/ip";
    if (!st->ifconfig_path) st->ifconfig_path="ifconfig";
    if (!st->route_path) st->route_path="route";

#ifndef HAVE_TUN_STREAMS
    if (st->tun_flavour==TUN_FLAVOUR_STREAMS) {
	cfgfatal(loc,"tun","TUN flavour STREAMS unsupported in this build "
		 "of secnet\n");
    }
#endif
#ifndef LINUX_TUN_SUPPORTED
    if (st->tun_flavour==TUN_FLAVOUR_LINUX) {
	cfgfatal(loc,"tun","TUN flavour LINUX unsupported in this build "
		 "of secnet\n");
    }
#endif

    /* Old TUN interface: the network interface name depends on which
       /dev/tunX file we open. If 'interface-search' is set to true, treat
       'device' as the prefix and try numbers from 0--255. If it's set
       to false, treat 'device' as the whole name, and require than an
       appropriate interface name be specified. */
    if (st->tun_flavour==TUN_FLAVOUR_BSD) {
	if (st->search_for_if && st->interface_name) {
	    cfgfatal(loc,"tun","you may not specify an interface name "
		     "in interface-search mode\n");
	}
	if (!st->search_for_if && !st->interface_name) {
	    cfgfatal(loc,"tun","you must specify an interface name "
		     "when you explicitly specify a TUN device file\n");
	}
    }

    add_hook(PHASE_GETRESOURCES,tun_phase_hook,st);

    return new_closure(&st->nl.cl);
}

static list_t *tun_apply(closure_t *self, struct cloc loc, dict_t *context,
			 list_t *args)
{
    return tun_create(self,loc,context,args,TUN_FLAVOUR_GUESS);
}

static list_t *tun_bsd_apply(closure_t *self, struct cloc loc, dict_t *context,
			     list_t *args)
{
    Message(M_WARNING,"(%s,%d): obsolete use of tun-old; replace with tun "
	    "and specify flavour \"bsd\".\n",loc.file,loc.line);
    return tun_create(self,loc,context,args,TUN_FLAVOUR_BSD);
}

void tun_module(dict_t *dict)
{
    add_closure(dict,"tun",tun_apply);
    add_closure(dict,"tun-old",tun_bsd_apply);
}
