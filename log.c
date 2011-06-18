#include "secnet.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <assert.h>
#include <unistd.h>
#include "process.h"

bool_t secnet_is_daemon=False;
uint32_t message_level=M_WARNING|M_ERR|M_SECURITY|M_FATAL;
struct log_if *system_log=NULL;

static void vMessage(uint32_t class, const char *message, va_list args)
{
    FILE *dest=stdout;
#define MESSAGE_BUFLEN 1023
    static char buff[MESSAGE_BUFLEN+1]={0,};
    uint32_t bp;
    char *nlp;

    if (secnet_is_daemon) {
	/* Messages go to the system log interface */
	bp=strlen(buff);
	vsnprintf(buff+bp,MESSAGE_BUFLEN-bp,message,args);
	/* Each line is sent separately */
	while ((nlp=strchr(buff,'\n'))) {
	    *nlp=0;
	    log(system_log,class,buff);
	    memmove(buff,nlp+1,strlen(nlp+1)+1);
	}
    } else {
	/* Messages go to stdout/stderr */
	if (class & message_level) {
	    if (class&M_FATAL || class&M_ERR || class&M_WARNING) {
		dest=stderr;
	    }
	    vfprintf(dest,message,args);
	}
    }
}  

void Message(uint32_t class, const char *message, ...)
{
    va_list ap;

    va_start(ap,message);
    vMessage(class,message,ap);
    va_end(ap);
}

static NORETURN(vfatal(int status, bool_t perror, const char *message,
		       va_list args));

static void vfatal(int status, bool_t perror, const char *message,
		   va_list args)
{
    int err;

    err=errno;

    enter_phase(PHASE_SHUTDOWN);
    Message(M_FATAL, "secnet fatal error: ");
    vMessage(M_FATAL, message, args);
    if (perror)
	Message(M_FATAL, ": %s\n",strerror(err));
    else
	Message(M_FATAL, "\n");
    exit(status);
}

void fatal(const char *message, ...)
{
    va_list args;
    va_start(args,message);
    vfatal(current_phase,False,message,args);
    va_end(args);
}

void fatal_status(int status, const char *message, ...)
{
    va_list args;
    va_start(args,message);
    vfatal(status,False,message,args);
    va_end(args);
}

void fatal_perror(const char *message, ...)
{
    va_list args;
    va_start(args,message);
    vfatal(current_phase,True,message,args);
    va_end(args);
}

void fatal_perror_status(int status, const char *message, ...)
{
    va_list args;
    va_start(args,message);
    vfatal(status,True,message,args);
    va_end(args);
}

void vcfgfatal_maybefile(FILE *maybe_f /* or 0 */, struct cloc loc,
			 cstring_t facility, const char *message, va_list args)
{
    enter_phase(PHASE_SHUTDOWN);

    if (maybe_f && ferror(maybe_f)) {
	assert(loc.file);
	Message(M_FATAL, "error reading config file (%s, %s): %s",
		facility, loc.file, strerror(errno));
    } else if (maybe_f && feof(maybe_f)) {
	assert(loc.file);
	Message(M_FATAL, "unexpected end of config file (%s, %s)",
		facility, loc.file);
    } else if (loc.file && loc.line) {
	Message(M_FATAL, "config error (%s, %s:%d): ",facility,loc.file,
		loc.line);
    } else if (!loc.file && loc.line) {
	Message(M_FATAL, "config error (%s, line %d): ",facility,loc.line);
    } else {
	Message(M_FATAL, "config error (%s): ",facility);
    }
    
    vMessage(M_FATAL,message,args);
    exit(current_phase);
}

void cfgfatal_maybefile(FILE *maybe_f, struct cloc loc, cstring_t facility,
			const char *message, ...)
{
    va_list args;

    va_start(args,message);
    vcfgfatal_maybefile(maybe_f,loc,facility,message,args);
    va_end(args);
}    

void cfgfatal(struct cloc loc, cstring_t facility, const char *message, ...)
{
    va_list args;

    va_start(args,message);
    vcfgfatal_maybefile(0,loc,facility,message,args);
    va_end(args);
}

void cfgfile_postreadcheck(struct cloc loc, FILE *f)
{
    assert(loc.file);
    if (ferror(f)) {
	Message(M_FATAL, "error reading config file (%s): %s",
		loc.file, strerror(errno));
	exit(current_phase);
    } else if (feof(f)) {
	Message(M_FATAL, "unexpected end of config file (%s)", loc.file);
	exit(current_phase);
    }
}

/* Take a list of log closures and merge them */
struct loglist {
    struct log_if *l;
    struct loglist *next;
};

static void log_vmulti(void *sst, int class, const char *message, va_list args)
{
    struct loglist *st=sst, *i;

    if (secnet_is_daemon) {
	for (i=st; i; i=i->next) {
	    i->l->vlog(i->l->st,class,message,args);
	}
    } else {
	vMessage(class,message,args);
	Message(class,"\n");
    }
}

static void log_multi(void *st, int priority, const char *message, ...)
{
    va_list ap;

    va_start(ap,message);
    log_vmulti(st,priority,message,ap);
    va_end(ap);
}

struct log_if *init_log(list_t *ll)
{
    int i=0;
    item_t *item;
    closure_t *cl;
    struct loglist *l=NULL, *n;
    struct log_if *r;

    if (list_length(ll)==1) {
	item=list_elem(ll,0);
	cl=item->data.closure;
	if (cl->type!=CL_LOG) {
	    cfgfatal(item->loc,"init_log","closure is not a logger");
	}
	return cl->interface;
    }
    while ((item=list_elem(ll,i++))) {
	if (item->type!=t_closure) {
	    cfgfatal(item->loc,"init_log","item is not a closure");
	}
	cl=item->data.closure;
	if (cl->type!=CL_LOG) {
	    cfgfatal(item->loc,"init_log","closure is not a logger");
	}
	n=safe_malloc(sizeof(*n),"init_log");
	n->l=cl->interface;
	n->next=l;
	l=n;
    }
    if (!l) {
	fatal("init_log: no log");
    }
    r=safe_malloc(sizeof(*r), "init_log");
    r->st=l;
    r->log=log_multi;
    r->vlog=log_vmulti;
    return r;
}

struct logfile {
    closure_t cl;
    struct log_if ops;
    struct cloc loc;
    string_t logfile;
    uint32_t level;
    FILE *f;
};

static cstring_t months[]={
    "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};

static void logfile_vlog(void *sst, int class, const char *message,
			 va_list args)
{
    struct logfile *st=sst;
    time_t t;
    struct tm *tm;

    if (secnet_is_daemon && st->f) {
	if (class&st->level) {
	    t=time(NULL);
	    tm=localtime(&t);
	    fprintf(st->f,"%s %2d %02d:%02d:%02d ",
		    months[tm->tm_mon],tm->tm_mday,tm->tm_hour,tm->tm_min,
		    tm->tm_sec);
	    vfprintf(st->f,message,args);
	    fprintf(st->f,"\n");
	    fflush(st->f);
	}
    } else {
	vMessage(class,message,args);
	Message(class,"\n");
    }
}

static void logfile_log(void *state, int class, const char *message, ...)
{
    va_list ap;

    va_start(ap,message);
    logfile_vlog(state,class,message,ap);
    va_end(ap);
}

static void logfile_hup_notify(void *sst, int signum)
{
    struct logfile *st=sst;
    FILE *f;
    f=fopen(st->logfile,"a");
    if (!f) {
	logfile_log(st,M_FATAL,"received SIGHUP, but could not reopen "
		    "logfile: %s",strerror(errno));
    } else {
	fclose(st->f);
	st->f=f;
	logfile_log(st,M_INFO,"received SIGHUP");
    }
}

static void logfile_phase_hook(void *sst, uint32_t new_phase)
{
    struct logfile *st=sst;
    FILE *f;

    if (background) {
	f=fopen(st->logfile,"a");
	if (!f) fatal_perror("logfile (%s:%d): cannot open \"%s\"",
			     st->loc.file,st->loc.line,st->logfile);
	st->f=f;
	request_signal_notification(SIGHUP, logfile_hup_notify,st);
    }
}

static struct flagstr message_class_table[]={
    { "debug-config", M_DEBUG_CONFIG },
    { "debug-phase", M_DEBUG_PHASE },
    { "debug", M_DEBUG },
    { "all-debug", M_DEBUG|M_DEBUG_PHASE|M_DEBUG_CONFIG },
    { "info", M_INFO },
    { "notice", M_NOTICE },
    { "warning", M_WARNING },
    { "error", M_ERR },
    { "security", M_SECURITY },
    { "fatal", M_FATAL },
    { "default", M_WARNING|M_ERR|M_SECURITY|M_FATAL },
    { "verbose", M_INFO|M_NOTICE|M_WARNING|M_ERR|M_SECURITY|M_FATAL },
    { "quiet", M_FATAL },
    { NULL, 0 }
};

static list_t *logfile_apply(closure_t *self, struct cloc loc, dict_t *context,
			     list_t *args)
{
    struct logfile *st;
    item_t *item;
    dict_t *dict;

    /* We should defer opening the logfile until the getresources
       phase.  We should defer writing into the logfile until after we
       become a daemon. */
    
    st=safe_malloc(sizeof(*st),"logfile_apply");
    st->cl.description="logfile";
    st->cl.type=CL_LOG;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.log=logfile_log;
    st->ops.vlog=logfile_vlog;
    st->loc=loc;
    st->f=NULL;

    item=list_elem(args,0);
    if (!item || item->type!=t_dict) {
	cfgfatal(loc,"logfile","argument must be a dictionary\n");
    }
    dict=item->data.dict;

    st->logfile=dict_read_string(dict,"filename",True,"logfile",loc);
    st->level=string_list_to_word(dict_lookup(dict,"class"),
				       message_class_table,"logfile");

    add_hook(PHASE_GETRESOURCES,logfile_phase_hook,st);

    return new_closure(&st->cl);
}

struct syslog {
    closure_t cl;
    struct log_if ops;
    string_t ident;
    int facility;
    bool_t open;
};

static int msgclass_to_syslogpriority(uint32_t m)
{
    switch (m) {
    case M_DEBUG_CONFIG: return LOG_DEBUG;
    case M_DEBUG_PHASE: return LOG_DEBUG;
    case M_DEBUG: return LOG_DEBUG;
    case M_INFO: return LOG_INFO;
    case M_NOTICE: return LOG_NOTICE;
    case M_WARNING: return LOG_WARNING;
    case M_ERR: return LOG_ERR;
    case M_SECURITY: return LOG_CRIT;
    case M_FATAL: return LOG_EMERG;
    default: return LOG_NOTICE;
    }
}
    
static void syslog_vlog(void *sst, int class, const char *message,
			 va_list args)
{
    struct syslog *st=sst;

    if (st->open)
	vsyslog(msgclass_to_syslogpriority(class),message,args);
    else {
	vMessage(class,message,args);
	Message(class,"\n");
    }
}

static void syslog_log(void *sst, int priority, const char *message, ...)
{
    va_list ap;

    va_start(ap,message);
    syslog_vlog(sst,priority,message,ap);
    va_end(ap);
}

static struct flagstr syslog_facility_table[]={
#ifdef LOG_AUTH
    { "auth", LOG_AUTH },
#endif
#ifdef LOG_AUTHPRIV
    { "authpriv", LOG_AUTHPRIV },
#endif
    { "cron", LOG_CRON },
    { "daemon", LOG_DAEMON },
    { "kern", LOG_KERN },
    { "local0", LOG_LOCAL0 },
    { "local1", LOG_LOCAL1 },
    { "local2", LOG_LOCAL2 },
    { "local3", LOG_LOCAL3 },
    { "local4", LOG_LOCAL4 },
    { "local5", LOG_LOCAL5 },
    { "local6", LOG_LOCAL6 },
    { "local7", LOG_LOCAL7 },
    { "lpr", LOG_LPR },
    { "mail", LOG_MAIL },
    { "news", LOG_NEWS },
    { "syslog", LOG_SYSLOG },
    { "user", LOG_USER },
    { "uucp", LOG_UUCP },
    { NULL, 0 }
};

static void syslog_phase_hook(void *sst, uint32_t newphase)
{
    struct syslog *st=sst;

    if (background) {
	openlog(st->ident,0,st->facility);
	st->open=True;
    }
}

static list_t *syslog_apply(closure_t *self, struct cloc loc, dict_t *context,
			    list_t *args)
{
    struct syslog *st;
    dict_t *d;
    item_t *item;
    string_t facstr;

    st=safe_malloc(sizeof(*st),"syslog_apply");
    st->cl.description="syslog";
    st->cl.type=CL_LOG;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.log=syslog_log;
    st->ops.vlog=syslog_vlog;

    item=list_elem(args,0);
    if (!item || item->type!=t_dict)
	cfgfatal(loc,"syslog","parameter must be a dictionary\n");
    d=item->data.dict;

    st->ident=dict_read_string(d, "ident", False, "syslog", loc);
    facstr=dict_read_string(d, "facility", True, "syslog", loc);
    st->facility=string_to_word(facstr,loc,
				syslog_facility_table,"syslog");
    st->open=False;
    add_hook(PHASE_GETRESOURCES,syslog_phase_hook,st);

    return new_closure(&st->cl);
}    

/* Read from a fd and output to a log.  This is a quick hack to
   support logging stderr, and needs code adding to tidy up before it
   can be used for anything else. */
#define FDLOG_BUFSIZE 1024
struct fdlog {
    struct log_if *log;
    int fd;
    cstring_t prefix;
    string_t buffer;
    int i;
    bool_t finished;
};

static int log_from_fd_beforepoll(void *sst, struct pollfd *fds, int *nfds_io,
				  int *timeout_io,
				  const struct timeval *tv_now, uint64_t *now)
{
    struct fdlog *st=sst;
    if (!st->finished) {
	*nfds_io=1;
	fds[0].fd=st->fd;
	fds[0].events=POLLIN;
    }
    return 0;
}

static void log_from_fd_afterpoll(void *sst, struct pollfd *fds, int nfds,
				  const struct timeval *tv_now, uint64_t *now)
{
    struct fdlog *st=sst;
    int r,remain,i;

    if (nfds==0) return;
    if (fds[0].revents&POLLERR) {
	st->finished=True;
    }
    if (fds[0].revents&POLLIN) {
	remain=FDLOG_BUFSIZE-st->i-1;
	if (remain<=0) {
	    st->buffer[FDLOG_BUFSIZE-1]=0;
	    st->log->log(st->log,M_WARNING,"%s: overlong line: %s",
			 st->prefix,st->buffer);
	    st->i=0;
	    remain=FDLOG_BUFSIZE-1;
	}
	r=read(st->fd,st->buffer+st->i,remain);
	if (r>0) {
	    st->i+=r;
	    for (i=0; i<st->i; i++) {
		if (st->buffer[i]=='\n') {
		    st->buffer[i]=0;
		    st->log->log(st->log->st,M_INFO,"%s: %s",
				 st->prefix,st->buffer);
		    i++;
		    memmove(st->buffer,st->buffer+i,st->i-i);
		    st->i-=i;
		    i=-1;
		}
	    }
	} else {
	    Message(M_WARNING,"log_from_fd: %s\n",strerror(errno));
	    st->finished=True;
	}
    }
}
		
void log_from_fd(int fd, cstring_t prefix, struct log_if *log)
{
    struct fdlog *st;

    st=safe_malloc(sizeof(*st),"log_from_fd");
    st->log=log;
    st->fd=fd;
    st->prefix=prefix;
    st->buffer=safe_malloc(FDLOG_BUFSIZE,"log_from_fd");
    st->i=0;
    st->finished=False;

    register_for_poll(st,log_from_fd_beforepoll,log_from_fd_afterpoll,1,
		      prefix);
}

init_module log_module;
void log_module(dict_t *dict)
{
    add_closure(dict,"logfile",logfile_apply);
    add_closure(dict,"syslog",syslog_apply);
}
