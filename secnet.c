/* $Log: secnet.c,v $
 * Revision 1.1  1996/03/13 22:27:41  sde1000
 * Initial revision
 *
 */

extern char version[];

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <adns.h>
#include <pwd.h>
#include <sys/types.h>

#include "secnet.h"
#include "util.h"
#include "conffile.h"

/* Command-line options (possibly config-file options too) */
static char *configfile="/etc/secnet/secnet.conf";
static char *userid=NULL;
static uid_t uid=0;
static bool_t background=True;
static char *pidfile=NULL;

/* Structures dealing with poll() call */
struct poll_interest {
    beforepoll_fn *before;
    afterpoll_fn *after;
    void *state;
    uint32_t max_nfds;
    uint32_t nfds;
    string_t desc;
    struct poll_interest *next;
};
static struct poll_interest *reg=NULL;
static uint32_t total_nfds=10;

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
	    {"silent", 0, 0, 'f'},
	    {"quiet", 0, 0, 'f'},
	    {"debug", 1, 0, 'd'},
	    {"config", 1, 0, 'c'},
	    {0,0,0,0}
	};

	c=getopt_long(argc, argv, "vwdnc:ft:",
		      long_options, &option_index);
	if (c==-1)
	    break;

	switch(c) {
	case 2:
	    /* Help */
	    fprintf(stderr,
		    "Usage: secnet [OPTION]...\n\n"
		    "  -f, --silent, --quiet   suppress error messages\n"
		    "  -w, --nowarnings        suppress warnings\n"
		    "  -v, --verbose           output extra diagnostics\n"
		    "  -c, --config=filename   specify a configuration file\n"
		    "  -n, --nodetach          do not run in background\n"
		    "  -d, --debug=item,...    set debug options\n"
		    "      --help              display this help and exit\n"
		    "      --version           output version information and exit\n"
		);
	    exit(0);
	    break;
      
	case 1:
	    /* Version */
	    fprintf(stderr,"%s\n",version);
	    exit(0);
	    break;

	case 'v':
	    message_level|=M_INFO|M_WARNING|M_ERROR|M_FATAL;
	    break;

	case 'n':
	    background=False;
	    break;

	case 'd':
	    message_level|=M_DEBUG_CONFIG|M_DEBUG_PHASE;
	    break;

	case 'f':
	    message_level=M_FATAL;
	    break;

	case 'c':
	    if (optarg)
		configfile=safe_strdup(optarg,"config_filename");
	    else
		fatal("secnet: no config filename specified");
	    break;

	case '?':
	    break;

	default:
	    Message(M_WARNING,"secnet: Unknown getopt code %c\n",c);
	}
    }

    if (argc-optind != 0) {
	Message(M_WARNING,"secnet: You gave extra command line parameters, "
		"which were ignored.\n");
    }
}

static void setup(dict_t *config)
{
    list_t *l;
    item_t *site;
    dict_t *system;
    struct log_if *log;
    struct passwd *pw;
    struct cloc loc;
    int i;

    l=dict_lookup(config,"system");

    if (!l || list_elem(l,0)->type!=t_dict) {
	fatal("configuration does not include a \"system\" dictionary\n");
    }
    system=list_elem(l,0)->data.dict;
    loc=list_elem(l,0)->loc;

    /* Arrange systemwide log facility */
    l=dict_lookup(system,"log");
    if (!l) {
	fatal("configuration does not include a system/log facility\n");
    }
    log=init_log(l);
    log->log(log->st,LOG_DEBUG,"%s: logging started",version);

    /* Who are we supposed to run as? */
    userid=dict_read_string(system,"userid",False,"system",loc);
    if (userid) {
	do {
	    pw=getpwent();
	    if (pw && strcmp(pw->pw_name,userid)==0) {
		uid=pw->pw_uid;
		break;
	    }
	} while(pw);
	endpwent();
	if (uid==0) {
	    fatal("userid \"%s\" not found\n",userid);
	}
    }

    /* Pidfile name */
    pidfile=dict_read_string(system,"pidfile",False,"system",loc);

    /* Go along site list, starting sites */
    l=dict_lookup(config,"sites");
    if (!l) {
	fatal("configuration did not define any remote sites\n");
    }
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
	s->control(s->st,True);
    }
}

void register_for_poll(void *st, beforepoll_fn *before,
		       afterpoll_fn *after, uint32_t max_nfds, string_t desc)
{
    struct poll_interest *i;

    i=safe_malloc(sizeof(*i),"register_for_poll");
    i->before=before;
    i->after=after;
    i->state=st;
    i->max_nfds=max_nfds;
    i->nfds=0;
    i->desc=desc;
    total_nfds+=max_nfds;
    i->next=reg;
    reg=i;
    return;
}

static void system_phase_hook(void *sst, uint32_t newphase)
{
    if (newphase==PHASE_SHUTDOWN && pidfile) {
	/* Try to unlink the pidfile; don't care if it fails */
	unlink(pidfile);
    }
}

static void run(void)
{
    struct timeval tv_now;
    uint64_t now;
    struct poll_interest *i;
    int rv, nfds, remain, idx;
    int timeout;
    struct pollfd *fds;

    fds=alloca(sizeof(*fds)*total_nfds);
    if (!fds) {
	fatal("run: couldn't alloca\n");
    }

    while (!finished) {
	if (gettimeofday(&tv_now, NULL)!=0) {
	    fatal_perror("main loop: gettimeofday");
	}
	now=(tv_now.tv_sec*1000)+(tv_now.tv_usec/1000);
	idx=0;
	for (i=reg; i; i=i->next) {
	    i->after(i->state, fds+idx, i->nfds, &tv_now, &now);
	    idx+=i->nfds;
	}
	remain=total_nfds;
	idx=0;
	timeout=-1;
	for (i=reg; i; i=i->next) {
	    nfds=remain;
	    rv=i->before(i->state, fds+idx, &nfds, &timeout, &tv_now, &now);
	    if (rv!=0) {
		/* XXX we need to handle this properly: increase the
		   nfds available */
		fatal("run: beforepoll_fn (%s) returns %d\n",i->desc,rv);
	    }
	    if (timeout<-1) {
		fatal("run: beforepoll_fn (%s) set timeout to %d\n",timeout);
	    }
	    idx+=nfds;
	    remain-=nfds;
	    i->nfds=nfds;
	}
	do {
	    rv=poll(fds, idx, timeout);
	    if (rv<0) {
		if (errno!=EINTR) {
		    fatal_perror("run: poll");
		}
	    }
	} while (rv<0);
    }
}

static void droppriv(void)
{
    FILE *pf=NULL;
    pid_t p;

    add_hook(PHASE_SHUTDOWN,system_phase_hook,NULL);

    /* Background now, if we're supposed to: we may be unable to write the
       pidfile if we don't. */
    if (background) {
	printf("goto background\n");
	/* Open the pidfile before forking - that way the parent can tell
	   whether it succeeds */
	if (pidfile) {
	    pf=fopen(pidfile,"w");
	    if (!pf) {
		fatal_perror("cannot open pidfile \"%s\"",pidfile);
	    }
	} else {
	    Message(M_WARNING,"secnet: no pidfile configured, but "
		    "backgrounding anyway\n");
	}
	p=fork();
	if (p>0) {
	    if (pf) {
		/* Parent process - write pidfile, exit */
		fprintf(pf,"%d\n",p);
		fclose(pf);
	    }
	    exit(0);
	} else if (p==0) {
	    /* Child process - all done, just carry on */
	    if (pf) fclose(pf);
	    printf("child\n");
	} else {
	    /* Error */
	    fatal_perror("cannot fork");
	    exit(1);
	}
    } else {
	if (pidfile) {
	    pf=fopen(pidfile,"w");
	    if (!pf) {
		fatal_perror("cannot open pidfile \"%s\"",pidfile);
	    }
	    fprintf(pf,"%d\n",getpid());
	    fclose(pf);
	}
    }

    /* Drop privilege now, if configured to do so */
    if (uid!=0) {
	if (setuid(uid)!=0) {
	    fatal_perror("can't set uid to \"%s\"",userid);
	}
    }
}

int main(int argc, char **argv)
{
    dict_t *config;

    enter_phase(PHASE_GETOPTS);
    parse_options(argc,argv);

    enter_phase(PHASE_READCONFIG);
    config=read_conffile(configfile);

    enter_phase(PHASE_SETUP);
    setup(config);
    
    enter_phase(PHASE_DROPPRIV);
    droppriv();

    enter_phase(PHASE_RUN);
    run();

    enter_phase(PHASE_SHUTDOWN);

    return 0;
}

