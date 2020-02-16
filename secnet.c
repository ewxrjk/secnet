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

#include "secnet.h"
#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <grp.h>

#include "util.h"
#include "conffile.h"
#include "process.h"

#if __APPLE__
/* apple's poll() does not work on char devs */
# define USE_SELECT 1
#endif

/* XXX should be from autoconf */
static const char *configfile="/etc/secnet/secnet.conf";
static const char *sites_key="sites";
bool_t just_check_config=False;
static char *userid=NULL;
static uid_t uid=0;
static gid_t gid;
bool_t background=True;
static char *pidfile=NULL;
bool_t require_root_privileges=False;
cstring_t require_root_privileges_explanation=NULL;

static pid_t secnet_pid;

/* Structures dealing with poll() call */
struct poll_interest {
    beforepoll_fn *before; /* 0 if deregistered and waiting to be deleted */
    afterpoll_fn *after;
    void *state;
    int32_t nfds;
    cstring_t desc;
    LIST_ENTRY(poll_interest) entry;
};
static LIST_HEAD(, poll_interest) reg = LIST_HEAD_INITIALIZER(&reg);

static bool_t interest_isregistered(const struct poll_interest *i)
{
    return !!i->before;
}

static bool_t finished=False;

/* Parse the command line options */
static void parse_options(int argc, char **argv)
{
    int c;

    while (True) {
	int option_index = 0;
	static struct option long_options[] = {
	    {"verbose", 0, 0, 'v'},
	    {"nowarnings", 0, 0, 'w'},
	    {"help", 0, 0, 2},
	    {"version", 0, 0, 1},
	    {"nodetach", 0, 0, 'n'},
	    {"managed", 0, 0, 'm'},
	    {"silent", 0, 0, 'f'},
	    {"quiet", 0, 0, 'f'},
	    {"debug", 0, 0, 'd'},
	    {"config", 1, 0, 'c'},
	    {"just-check-config", 0, 0, 'j'},
	    {"sites-key", 1, 0, 's'},
	    {0,0,0,0}
	};

	c=getopt_long(argc, argv, "vwdnjc:ft:s:m",
		      long_options, &option_index);
	if (c==-1)
	    break;

	switch(c) {
	case 2:
	    /* Help */
	    printf("Usage: secnet [OPTION]...\n\n"
		   "  -f, --silent, --quiet   suppress error messages\n"
		   "  -w, --nowarnings        suppress warnings\n"
		   "  -v, --verbose           output extra diagnostics\n"
		   "  -c, --config=filename   specify a configuration file\n"
		   "  -j, --just-check-config stop after reading "
		   "configuration file\n"
		   "  -s, --sites-key=name    configuration key that "
		   "specifies active sites\n"
		   "  -n, --nodetach          do not run in background\n"
		   "  -m, --managed           running under a supervisor\n"
		   "  -d, --debug             output debug messages\n"
		   "      --help              display this help and exit\n"
		   "      --version           output version information "
		   "and exit\n"
		);
	    exit(0);
	    break;
      
	case 1:
	    /* Version */
	    printf("%s\n",version);
	    exit(0);
	    break;

	case 'd':
	    message_level|=M_DEBUG_CONFIG|M_DEBUG_PHASE|M_DEBUG;
	    /* fall through */
	case 'v':
	    message_level|=M_INFO|M_NOTICE|M_WARNING|M_ERR|M_SECURITY|
		M_FATAL;
	    break;

	case 'w':
	    message_level&=(~M_WARNING);
	    break;

	case 'f':
	    message_level=M_FATAL;
	    break;

	case 'n':
	    background=False;
	    break;

	case 'm':
	    secnet_is_daemon=True;
	    break;

	case 'c':
	    if (optarg)
		configfile=safe_strdup(optarg,"config_filename");
	    else
		fatal("secnet: no config filename specified");
	    break;

	case 'j':
	    just_check_config=True;
	    break;

	case 's':
	    if (optarg)
		sites_key=safe_strdup(optarg,"sites-key");
	    else
		fatal("secnet: no sites key specified");
	    break;

	case '?':
	    exit(1);
	    break;

	default:
	    Message(M_ERR,"secnet: Unknown getopt code %c\n",c);
	}
    }

    if (argc-optind != 0) {
	Message(M_ERR,"secnet: You gave extra command line parameters, "
		"which were ignored.\n");
    }
}

static void setup(dict_t *config)
{
    list_t *l;
    dict_t *system;
    struct passwd *pw;
    struct cloc loc;

    l=dict_lookup(config,"system");

    if (!l || list_elem(l,0)->type!=t_dict) {
	fatal("configuration does not include a \"system\" dictionary");
    }
    system=list_elem(l,0)->data.dict;
    loc=list_elem(l,0)->loc;

    /* Arrange systemwide log facility */
    l=dict_lookup(system,"log");
    if (!l) {
	fatal("configuration does not include a system/log facility");
    }
    system_log=init_log(l);

    /* Who are we supposed to run as? */
    userid=dict_read_string(system,"userid",False,"system",loc);
    if (userid) {
	if (!(pw=getpwnam(userid)))
	    fatal("userid \"%s\" not found",userid);
	uid=pw->pw_uid;
	gid=pw->pw_gid;
    }

    /* Pidfile name */
    pidfile=dict_read_string(system,"pidfile",False,"system",loc);

    /* Check whether we need root privileges */
    if (require_root_privileges && uid!=0) {
	fatal("the configured feature \"%s\" requires "
	      "that secnet retain root privileges while running.",
	      require_root_privileges_explanation);
    }
}

static void start_sites(dict_t *config) {
    int i;
    list_t *l;
    item_t *site;

    /* Go along site list, starting sites */
    l=dict_lookup(config,sites_key);
    if (!l) {
	Message(M_WARNING,"secnet: configuration key \"%s\" is missing; no "
		"remote sites are defined\n",sites_key);
    } else {
	i=0;
	while ((site=list_elem(l, i++))) {
	    struct site_if *s;
	    if (site->type!=t_closure) {
		cfgfatal(site->loc,"system","non-closure in site list");
	    }
	    if (site->data.closure->type!=CL_SITE) {
		cfgfatal(site->loc,"system","non-site closure in site list");
	    }
	    s=site->data.closure->interface;
	    s->startup(s->st);
	}
    }
}

struct poll_interest *register_for_poll(void *st, beforepoll_fn *before,
		       afterpoll_fn *after, cstring_t desc)
{
    struct poll_interest *i;

    NEW(i);
    i->before=before;
    i->after=after;
    i->state=st;
    i->nfds=0;
    i->desc=desc;
    LIST_INSERT_HEAD(&reg, i, entry);
    return i;
}

void deregister_for_poll(struct poll_interest *i)
{
    /* We cannot simply throw this away because we're reentrantly
     * inside the main loop, which needs to remember which range of
     * fds corresponds to this now-obsolete interest */
    i->before=0;
}

static void system_phase_hook(void *sst, uint32_t newphase)
{
    if (newphase==PHASE_SHUTDOWN && pidfile) {
	/* Try to unlink the pidfile; don't care if it fails */
	unlink(pidfile);
    }
}

#if USE_SELECT
static int fakepoll(struct pollfd *fds, int nfds, int timeout) {
    fd_set infds[1], outfds[1];
    int maxfd = -1, i, rc;
    struct timeval tvtimeout;
    FD_ZERO(infds);
    FD_ZERO(outfds);
    for(i = 0; i < nfds; ++i) {
	if(fds[i].events & POLLIN)
	    FD_SET(fds[i].fd, infds);
	if(fds[i].events & POLLOUT)
	    FD_SET(fds[i].fd, outfds);
	if(fds[i].fd > maxfd)
	    maxfd = fds[i].fd;
    }
    if(timeout != -1) {
	tvtimeout.tv_sec = timeout / 1000;
	tvtimeout.tv_usec = 1000 * (timeout % 1000);
    }
    rc = select(maxfd + 1, infds, outfds, NULL, 
		timeout == -1 ? NULL : &tvtimeout);
    if(rc >= 0) {
	for(i = 0; i < nfds; ++i) {
	    int revents = 0;
	    if(FD_ISSET(fds[i].fd, infds))
		revents |= POLLIN;
	    if(FD_ISSET(fds[i].fd, outfds))
		revents |= POLLOUT;
	    fds[i].revents = revents;
	}
    }
    return rc;
}
#endif

struct timeval tv_now_global;
uint64_t now_global;

static void run(void)
{
    struct poll_interest *i, *itmp;
    int rv, nfds, idx;
    int timeout;
    struct pollfd *fds=0;
    int allocdfds=0, shortfall=0;

    do {
	if (gettimeofday(&tv_now_global, NULL)!=0) {
	    fatal_perror("main loop: gettimeofday");
	}
	now_global=((uint64_t)tv_now_global.tv_sec*(uint64_t)1000)+
	           ((uint64_t)tv_now_global.tv_usec/(uint64_t)1000);
	idx=0;
	LIST_FOREACH(i, &reg, entry) {
	    int check;
	    if (interest_isregistered(i)) {
		for (check=0; check<i->nfds; check++) {
		    if(fds[idx+check].revents & POLLNVAL) {
			fatal("run: poll (%s#%d) set POLLNVAL", i->desc, check);
		    }
		}
		i->after(i->state, fds+idx, i->nfds);
	    }
	    idx+=i->nfds;
	}
	if (shortfall) {
	    allocdfds *= 2;
	    allocdfds += shortfall;
	    REALLOC_ARY(fds,allocdfds);
	}
	shortfall=0;
	idx=0;
	timeout=-1;
	LIST_FOREACH_SAFE(i, &reg, entry, itmp) {
	    int remain=allocdfds-idx;
	    nfds=remain;
	    if (interest_isregistered(i)) {
		rv=i->before(i->state, fds+idx, &nfds, &timeout);
		if (rv!=0) {
		    if (rv!=ERANGE)
			fatal("run: beforepoll_fn (%s) returns %d",i->desc,rv);
		    assert(nfds < INT_MAX/4 - shortfall);
		    shortfall += nfds-remain;
		    nfds=0;
		    timeout=0;
		}
	    } else {
		nfds=0;
	    }
	    if (timeout<-1) {
		fatal("run: beforepoll_fn (%s) set timeout to %d",
		      i->desc,timeout);
	    }
	    if (!interest_isregistered(i)) {
		/* check this here, rather than earlier, so that we
		   handle the case where i->before() calls deregister */
		LIST_REMOVE(i, entry);
		free(i);
		continue;
	    }
	    idx+=nfds;
	    i->nfds=nfds;
	}
	do {
	    if (finished) break;
#if USE_SELECT
	    rv=fakepoll(fds, idx, timeout);
#else
	    rv=poll(fds, idx, timeout);
#endif
	    if (rv<0) {
		if (errno!=EINTR) {
		    fatal_perror("run: poll");
		}
	    }
	} while (rv<0);
    } while (!finished);
    free(fds);
}

bool_t will_droppriv(void)
{
    assert(current_phase >= PHASE_SETUP);
    return !!uid;
}

/* Surrender privileges, if necessary */
static void droppriv(void)
{
    if (userid) {
	if (setgid(gid)!=0)
	    fatal_perror("can't set gid to %ld",(long)gid);
	if (initgroups(userid, gid) < 0)
	    fatal_perror("initgroups");	
	if (setuid(uid)!=0) {
	    fatal_perror("can't set uid to \"%s\"",userid);
	}
	assert(getuid() == uid);
	assert(geteuid() == uid);
	assert(getgid() == gid);
	assert(getegid() == gid);
    }
}

/* Become a daemon, if necessary */
static void become_daemon(void)
{
    FILE *pf=NULL;
    pid_t p;
    int errfds[2];

    add_hook(PHASE_SHUTDOWN,system_phase_hook,NULL);

    /* We only want to become a daemon if we are not one
     already */
    if (background && !secnet_is_daemon) {
	p=fork();
	if (p>0) {
	    /* Parent process - just exit */
	    _exit(0);
	} else if (p==0) {
	    /* Child process - all done, just carry on */
	    secnet_is_daemon=True;
	    if (setsid() < 0)
		fatal_perror("setsid");
	} else {
	    /* Error */
	    fatal_perror("cannot fork");
	    exit(1);
	}
    }
    if (secnet_is_daemon) {
	/* stderr etc are redirected to the system/log facility */
	pipe_cloexec(errfds);
	if (dup2(errfds[1],0) < 0
	    || dup2(errfds[1],1) < 0
	    || dup2(errfds[1],2) < 0)
	    fatal_perror("can't dup2 pipe");
	if (close(errfds[1]) < 0)
	    fatal_perror("can't close redundant pipe endpoint");
	log_from_fd(errfds[0],"stderr",system_log);
    }
    secnet_pid=getpid();
    
    /* Now we can write the pidfile */
    if (pidfile) {
	pf=fopen(pidfile,"w");
	if (!pf) {
	    fatal_perror("cannot open pidfile \"%s\"",pidfile);
	}
	if (fprintf(pf,"%ld\n",(long)secnet_pid) < 0
	    || fclose(pf) < 0)
	    fatal_perror("cannot write to pidfile \"%s\"",pidfile);
    }
}

static signal_notify_fn finish,ignore_hup;
static void finish(void *st, int signum)
{
    finished=True;
    Message(M_NOTICE,"%s [%d]: received %s\n",version,secnet_pid,(string_t)st);
}
static void ignore_hup(void *st, int signum)
{
    Message(M_INFO,"%s [%d]: received SIGHUP\n",version,secnet_pid);
    return;
}

int main(int argc, char **argv)
{
    dict_t *config;

    log_early_init();
    phase_hooks_init();

    enter_phase(PHASE_GETOPTS);
    parse_options(argc,argv);

    enter_phase(PHASE_READCONFIG);
    config=read_conffile(configfile);

    enter_phase(PHASE_SETUP);
    setup(config);
    start_sites(config);

    if (just_check_config) {
	Message(M_INFO,"configuration file check complete\n");
	exit(0);
    }

    enter_phase(PHASE_DAEMONIZE);
    become_daemon();
    Message(M_NOTICE,"%s [%d]: starting\n",version,secnet_pid);
    
    enter_phase(PHASE_GETRESOURCES);
    /* Appropriate phase hooks will have been run */
    
    enter_phase(PHASE_DROPPRIV);
    droppriv();

    start_signal_handling();
    request_signal_notification(SIGTERM,finish,safe_strdup("SIGTERM","run"));
    if (!background) request_signal_notification(SIGINT,finish,
						 safe_strdup("SIGINT","run"));
    request_signal_notification(SIGHUP,ignore_hup,NULL);
    enter_phase(PHASE_RUN);
    run();

    enter_phase(PHASE_SHUTDOWN);
    Message(M_NOTICE,"%s [%d]: finished\n",version,secnet_pid);

    return 0;
}
