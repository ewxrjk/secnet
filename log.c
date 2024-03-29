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
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <assert.h>
#include <unistd.h>
#include "process.h"
#include "util.h"

bool_t secnet_is_daemon=False;
uint32_t message_level=M_WARNING|M_ERR|M_SECURITY|M_FATAL;
struct log_if *system_log=NULL;

FORMAT(printf,2,0)
static void vMessageFallback(uint32_t class, const char *message, va_list args)
{
    FILE *dest=stdout;
    /* Messages go to stdout/stderr */
    if (class & message_level) {
	if (class&M_FATAL || class&M_ERR || class&M_WARNING) {
	    dest=stderr;
	}
	vfprintf(dest,message,args);
    }
}

FORMAT(printf,2,0)
static void vMessage(uint32_t class, const char *message, va_list args)
{

    vslilog_part(system_log, class, message, args);
}  

void Message(uint32_t class, const char *message, ...)
{
    va_list ap;

    va_start(ap,message);
    vMessage(class,message,ap);
    va_end(ap);
}

FORMAT(printf,2,3)
static void MessageFallback(uint32_t class, const char *message, ...)
{
    va_list ap;

    va_start(ap,message);
    vMessageFallback(class,message,ap);
    va_end(ap);
}

static NORETURN(vfatal(int status, bool_t perror, const char *message,
		       va_list args));

FORMAT(printf,3,0)
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
			 cstring_t facility, const char *message, va_list args,
			 const char *suffix)
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
    Message(M_FATAL,"%s",suffix);
    exit(current_phase);
}

void cfgfatal_maybefile(FILE *maybe_f, struct cloc loc, cstring_t facility,
			const char *message, ...)
{
    va_list args;

    va_start(args,message);
    vcfgfatal_maybefile(maybe_f,loc,facility,message,args,0);
    va_end(args);
}    

void cfgfatal_cl_type(struct cloc loc, const char *facility,
		      closure_t *cl, uint32_t exp_type, const char *name)
{
    char expbuf[10], gotbuf[10];
    assert(cl->type != exp_type);
    const char *exp = closure_type_name(exp_type, expbuf);
    const char *got = closure_type_name(cl->type, gotbuf);
    cfgfatal(loc,facility,
	     "\"%s\" is the wrong type of closure (expected %s, got %s)\n",
	     name, exp, got);
}

void cfgfatal(struct cloc loc, cstring_t facility, const char *message, ...)
{
    va_list args;

    va_start(args,message);
    vcfgfatal_maybefile(0,loc,facility,message,args,"");
    va_end(args);
}

void cfgfile_log__vmsg(void *sst, int class, const char *message, va_list args)
{
    struct cfgfile_log *st=sst;
    vcfgfatal_maybefile(0,st->loc,st->facility,message,args,"\n");
}

void cfgfile_postreadcheck(struct cloc loc, FILE *f)
{
    assert(loc.file);
    if (ferror(f)) {
	Message(M_FATAL, "error reading config file (%s): %s\n",
		loc.file, strerror(errno));
	exit(current_phase);
    } else if (feof(f)) {
	Message(M_FATAL, "unexpected end of config file (%s)\n", loc.file);
	exit(current_phase);
    }
}

/* Take a list of log closures and merge them */
struct loglist {
    struct log_if *l;
    struct loglist *next;
};

FORMAT(printf, 3, 0)
static void log_vmulti(void *sst, int class, const char *message, va_list args)
{
    struct loglist *st=sst, *i;

    if (secnet_is_daemon) {
	for (i=st; i; i=i->next) {
	    vslilog(i->l,class,message,args);
	}
    } else {
	vMessage(class,message,args);
	Message(class,"\n");
    }
}

FORMAT(printf, 6, 0)
void lg_vperror(struct log_if *lg, const char *desc, struct cloc *loc,
		int class, int errnoval, const char *fmt, va_list al)
{
    int status=current_phase;
    int esave=errno;

    if (!lg)
	lg=system_log;

    if (class & M_FATAL)
	enter_phase(PHASE_SHUTDOWN);

    slilog_part(lg,class,"%s",desc);
    if (loc)
	slilog_part(lg,class," (%s:%d)",loc->file,loc->line);
    slilog_part(lg,class,": ");
    vslilog_part(lg,class,fmt,al);
    if (errnoval)
	slilog_part(lg,class,": %s",strerror(errnoval));
    slilog_part(lg,class,"\n");

    if (class & M_FATAL)
	exit(status);

    errno=esave;
}

void lg_perror(struct log_if *lg, const char *desc, struct cloc *loc,
	       int class, int errnoval, const char *fmt, ...)
{
    va_list al;
    va_start(al,fmt);
    lg_vperror(lg,desc,loc,class,errnoval,fmt,al);
    va_end(al);
}

void lg_exitstatus(struct log_if *lg, const char *desc, struct cloc *loc,
		   int class, int status, const char *progname)
{
    if (!status)
	lg_perror(lg,desc,loc,class,0,"%s exited",progname);
    else if (WIFEXITED(status))
	lg_perror(lg,desc,loc,class,0,"%s exited with error exit status %d",
		  progname,WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
	lg_perror(lg,desc,loc,class,0,"%s died due to fatal signal %s (%d)%s",
		  progname,strsignal(WTERMSIG(status)),WTERMSIG(status),
		  WCOREDUMP(status)?" (core dumped)":"");
    else
	lg_perror(lg,desc,loc,class,0,"%s died with unknown wait status %d",
		  progname,status);
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
	NEW(n);
	n->l=cl->interface;
	n->next=l;
	l=n;
    }
    if (!l) {
	fatal("init_log: no log");
    }
    NEW(r);
    r->st=l;
    r->vlogfn=log_vmulti;
    r->buff[0]=0;
    return r;
}

struct logfile {
    closure_t cl;
    struct log_if ops;
    struct cloc loc;
    string_t logfile;
    uint32_t level;
    FILE *f;
    const char *prefix;
    bool_t forked;
};

static cstring_t months[]={
    "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};

FORMAT(printf, 3, 0)
static void logfile_vlog(void *sst, int class, const char *message,
			 va_list args)
{
    struct logfile *st=sst;
    time_t t;
    struct tm *tm;
    char pidbuf[20];

    if (st->forked) {
	pid_t us=getpid();
	snprintf(pidbuf,sizeof(pidbuf),"[%ld] ",(long)us);
    } else {
	pidbuf[0]=0;
    }

    if (class&st->level) {
	t=time(NULL);
	tm=localtime(&t);
	fprintf(st->f,"%s %2d %02d:%02d:%02d %s%s%s",
		months[tm->tm_mon],tm->tm_mday,tm->tm_hour,tm->tm_min,
		tm->tm_sec,
		st->prefix, st->prefix[0] ? " " : "",
		pidbuf);
	vfprintf(st->f,message,args);
	fprintf(st->f,"\n");
	fflush(st->f);
    }
}

FORMAT(printf,3,4)
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
    if (!st->logfile) return;
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

    if (background && st->logfile) {
	f=fopen(st->logfile,"a");
	if (!f) fatal_perror("logfile (%s:%d): cannot open \"%s\"",
			     st->loc.file,st->loc.line,st->logfile);
	st->f=f;
	request_signal_notification(SIGHUP, logfile_hup_notify,st);
    }
}

static void logfile_childpersist_hook(void *sst, uint32_t new_phase)
{
    struct logfile *st=sst;
    st->forked=1;
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

static void logfile_file_init(struct logfile *st, FILE *f, const char *desc)
{
    st->cl.description=desc;
    st->cl.type=CL_LOG;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.vlogfn=logfile_vlog;
    st->ops.buff[0]=0;
    st->f=f;
    st->logfile=0;
    st->prefix="";
    st->forked=0;
    st->loc.file=0;
    st->loc.line=-1;
}

static list_t *logfile_apply(closure_t *self, struct cloc loc, dict_t *context,
			     list_t *args)
{
    struct logfile *st;
    item_t *item;
    dict_t *dict;

    /* We should defer opening the logfile until the getresources
       phase.  We should defer writing into the logfile until after we
       become a daemon. */
    
    NEW(st);
    st->loc=loc;
    logfile_file_init(st,stderr,"logfile");

    item=list_elem(args,0);
    if (!item || item->type!=t_dict) {
	cfgfatal(loc,"logfile","argument must be a dictionary\n");
    }
    dict=item->data.dict;

    st->logfile=dict_read_string(dict,"filename",False,"logfile",loc);
    st->prefix=dict_read_string(dict,"prefix",False,"logfile",loc);
    if (!st->prefix) st->prefix="";
    st->level=string_list_to_word(dict_lookup(dict,"class"),
				       message_class_table,"logfile");

    add_hook(PHASE_DAEMONIZE,logfile_phase_hook,st);
    add_hook(PHASE_CHILDPERSIST,logfile_childpersist_hook,st);

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
    FORMAT(printf,3,0);
static void syslog_vlog(void *sst, int class, const char *message,
			 va_list args)
{
    struct syslog *st=sst;

    if (st->open)
	vsyslog(msgclass_to_syslogpriority(class),message,args);
    else {
	vMessageFallback(class,message,args);
	MessageFallback(class,"\n");
    }
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
	openlog(st->ident,
		newphase==PHASE_CHILDPERSIST ? LOG_PID : 0,
		st->facility);
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

    NEW(st);
    st->cl.description="syslog";
    st->cl.type=CL_LOG;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.vlogfn=syslog_vlog;
    st->ops.buff[0]=0;

    item=list_elem(args,0);
    if (!item || item->type!=t_dict)
	cfgfatal(loc,"syslog","parameter must be a dictionary\n");
    d=item->data.dict;

    st->ident=dict_read_string(d, "ident", False, "syslog", loc);
    facstr=dict_read_string(d, "facility", True, "syslog", loc);
    st->facility=string_to_word(facstr,loc,
				syslog_facility_table,"syslog");
    st->open=False;
    add_hook(PHASE_DAEMONIZE,syslog_phase_hook,st);
    add_hook(PHASE_CHILDPERSIST,syslog_phase_hook,st);

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
				  int *timeout_io)
{
    struct fdlog *st=sst;
    if (!st->finished) {
	BEFOREPOLL_WANT_FDS(1);
	fds[0].fd=st->fd;
	fds[0].events=POLLIN;
    } else {
	BEFOREPOLL_WANT_FDS(0);
    }
    return 0;
}

static void log_from_fd_afterpoll(void *sst, struct pollfd *fds, int nfds)
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
	    slilog(st->log,M_WARNING,"%s: overlong line: %s",
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
		    slilog(st->log,M_INFO,"%s: %s",
				 st->prefix,st->buffer);
		    i++;
		    memmove(st->buffer,st->buffer+i,st->i-i);
		    st->i-=i;
		    i=-1;
		}
	    }
	} else if (errno==EINTR || iswouldblock(errno)) {
	} else {
	    Message(M_WARNING,"log_from_fd: %s\n",strerror(errno));
	    st->finished=True;
	}
    }
}
		
void log_from_fd(int fd, cstring_t prefix, struct log_if *log)
{
    struct fdlog *st;

    NEW(st);
    st->log=log;
    st->fd=fd;
    st->prefix=prefix;
    st->buffer=safe_malloc(FDLOG_BUFSIZE,"log_from_fd");
    st->i=0;
    st->finished=False;

    setnonblock(st->fd);

    register_for_poll(st,log_from_fd_beforepoll,log_from_fd_afterpoll,
		      prefix);
}

static struct logfile startup_log;
void log_early_setlevel(void)
{
    startup_log.level=message_level;
}
void log_early_init(void)
{
    logfile_file_init(&startup_log,stderr,"startup");
    log_early_setlevel();
    system_log=&startup_log.ops;;
}

/* for the benefit of main, really */
void logfile_init_file(struct logfile *st, FILE *f);

void log_module(dict_t *dict)
{
    setlinebuf(stderr);

    add_closure(dict,"logfile",logfile_apply);
    add_closure(dict,"syslog",syslog_apply);
}
