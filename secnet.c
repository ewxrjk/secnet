extern char version[];

#include "secnet.h"
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pwd.h>

#include "util.h"
#include "conffile.h"
#include "process.h"

/* XXX should be from autoconf */
static const char *configfile="/etc/secnet/secnet.conf";
static const char *sites_key="sites";
bool_t just_check_config=False;
static char *userid=NULL;
static uid_t uid=0;
bool_t background=True;
static char *pidfile=NULL;
bool_t require_root_privileges=False;
cstring_t require_root_privileges_explanation=NULL;

static pid_t secnet_pid;

/* from log.c */
extern uint32_t message_level;
extern bool_t secnet_is_daemon;
extern struct log_if *system_log;

/* from process.c */
extern void start_signal_handling(void);

/* Structures dealing with poll() call */
struct poll_interest {
    beforepoll_fn *before;
    afterpoll_fn *after;
    void *state;
    uint32_t max_nfds;
    uint32_t nfds;
    cstring_t desc;
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
	    {"just-check-config", 0, 0, 'j'},
	    {"sites-key", 1, 0, 's'},
	    {0,0,0,0}
	};

	c=getopt_long(argc, argv, "vwdnjc:ft:s:",
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
		   "  -d, --debug=item,...    set debug options\n"
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

	case 'v':
	    message_level|=M_INFO|M_NOTICE|M_WARNING|M_ERR|M_SECURITY|
		M_FATAL;
	    break;

	case 'w':
	    message_level&=(~M_WARNING);
	    break;

	case 'd':
	    message_level|=M_DEBUG_CONFIG|M_DEBUG_PHASE|M_DEBUG;
	    break;

	case 'f':
	    message_level=M_FATAL;
	    break;

	case 'n':
	    background=False;
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
    item_t *site;
    dict_t *system;
    struct passwd *pw;
    struct cloc loc;
    int i;

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
	do {
	    pw=getpwent();
	    if (pw && strcmp(pw->pw_name,userid)==0) {
		uid=pw->pw_uid;
		break;
	    }
	} while(pw);
	endpwent();
	if (uid==0) {
	    fatal("userid \"%s\" not found",userid);
	}
    }

    /* Pidfile name */
    pidfile=dict_read_string(system,"pidfile",False,"system",loc);

    /* Check whether we need root privileges */
    if (require_root_privileges && uid!=0) {
	fatal("the configured feature \"%s\" requires "
	      "that secnet retain root privileges while running.",
	      require_root_privileges_explanation);
    }

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
	    s->control(s->st,True);
	}
    }
}

void register_for_poll(void *st, beforepoll_fn *before,
		       afterpoll_fn *after, uint32_t max_nfds, cstring_t desc)
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

    fds=safe_malloc(sizeof(*fds)*total_nfds, "run");

    Message(M_NOTICE,"%s [%d]: starting\n",version,secnet_pid);

    do {
	if (gettimeofday(&tv_now, NULL)!=0) {
	    fatal_perror("main loop: gettimeofday");
	}
	now=((uint64_t)tv_now.tv_sec*(uint64_t)1000)+
	    ((uint64_t)tv_now.tv_usec/(uint64_t)1000);
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
		fatal("run: beforepoll_fn (%s) returns %d",i->desc,rv);
	    }
	    if (timeout<-1) {
		fatal("run: beforepoll_fn (%s) set timeout to %d",timeout);
	    }
	    idx+=nfds;
	    remain-=nfds;
	    i->nfds=nfds;
	}
	do {
	    if (finished) break;
	    rv=poll(fds, idx, timeout);
	    if (rv<0) {
		if (errno!=EINTR) {
		    fatal_perror("run: poll");
		}
	    }
	} while (rv<0);
    } while (!finished);
    free(fds);
}

static void droppriv(void)
{
    FILE *pf=NULL;
    pid_t p;
    int errfds[2];

    add_hook(PHASE_SHUTDOWN,system_phase_hook,NULL);

    /* Open the pidfile for writing now: we may be unable to do so
       once we drop privileges. */
    if (pidfile) {
	pf=fopen(pidfile,"w");
	if (!pf) {
	    fatal_perror("cannot open pidfile \"%s\"",pidfile);
	}
    }
    if (!background && pf) {
	fprintf(pf,"%d\n",getpid());
	fclose(pf);
    }

    /* Now drop privileges */
    if (uid!=0) {
	if (setuid(uid)!=0) {
	    fatal_perror("can't set uid to \"%s\"",userid);
	}
    }
    if (background) {
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
	    /* Close stdin and stdout; we don't need them any more.
               stderr is redirected to the system/log facility */
	    if (pipe(errfds)!=0) {
		fatal_perror("can't create pipe for stderr");
	    }
	    close(0);
	    close(1);
	    close(2);
	    dup2(errfds[1],0);
	    dup2(errfds[1],1);
	    dup2(errfds[1],2);
	    secnet_is_daemon=True;
	    setsid();
	    log_from_fd(errfds[0],"stderr",system_log);
	} else {
	    /* Error */
	    fatal_perror("cannot fork");
	    exit(1);
	}
    }
    secnet_pid=getpid();
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

    enter_phase(PHASE_GETOPTS);
    parse_options(argc,argv);

    enter_phase(PHASE_READCONFIG);
    config=read_conffile(configfile);

    enter_phase(PHASE_SETUP);
    setup(config);

    if (just_check_config) {
	Message(M_INFO,"configuration file check complete\n");
	exit(0);
    }

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
