/*
 * util.c
 * - output and logging support
 * - program lifetime support
 * - IP address and subnet munging routines
 * - MPI convenience functions
 */
/*
 *  This file is
 *    Copyright (C) 1995--2001 Stephen Early <steve@greenend.org.uk>
 *
 *  It is part of secnet, which is
 *    Copyright (C) 1995--2001 Stephen Early <steve@greenend.org.uk>
 *    Copyright (C) 1998 Ross Anderson, Eli Biham, Lars Knudsen
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. 
 */

#include "secnet.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>
#include <sys/wait.h>
#include <time.h>
#include "util.h"
#include "unaligned.h"

#define MIN_BUFFER_SIZE 64
#define DEFAULT_BUFFER_SIZE 4096
#define MAX_BUFFER_SIZE 131072

static char *hexdigits="0123456789abcdef";

bool_t secnet_is_daemon=False;
uint32_t message_level=M_WARNING|M_ERROR|M_SECURITY|M_FATAL;
struct log_if *system_log=NULL;
static uint32_t current_phase=0;

struct phase_hook {
    hook_fn *fn;
    void *state;
    struct phase_hook *next;
};

static struct phase_hook *hooks[NR_PHASES]={NULL,};

static void vMessage(uint32_t class, char *message, va_list args)
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
	    if (class&M_FATAL || class&M_ERROR || class&M_WARNING) {
		dest=stderr;
	    }
	    vfprintf(dest,message,args);
	}
    }
}  

void Message(uint32_t class, char *message, ...)
{
    va_list ap;

    va_start(ap,message);
    vMessage(class,message,ap);
    va_end(ap);
}

static void vfatal(int status, bool_t perror, char *message, va_list args)
{
    int err;

    err=errno;

    enter_phase(PHASE_SHUTDOWN);
    if (perror) {
	Message(M_FATAL, "secnet fatal error: ");
	vMessage(M_FATAL, message, args);
	Message(M_FATAL, ": %s\n",strerror(err));
    }
    else {
	Message(M_FATAL, "secnet fatal error: ");
	vMessage(M_FATAL,message,args);
    }
    exit(status);
}

void fatal(char *message, ...)
{
    va_list args;
    va_start(args,message);
    vfatal(current_phase,False,message,args);
    va_end(args);
}

void fatal_status(int status, char *message, ...)
{
    va_list args;
    va_start(args,message);
    vfatal(status,False,message,args);
    va_end(args);
}

void fatal_perror(char *message, ...)
{
    va_list args;
    va_start(args,message);
    vfatal(current_phase,True,message,args);
    va_end(args);
}

void fatal_perror_status(int status, char *message, ...)
{
    va_list args;
    va_start(args,message);
    vfatal(status,True,message,args);
    va_end(args);
}

void cfgfatal(struct cloc loc, string_t facility, char *message, ...)
{
    va_list args;

    va_start(args,message);

    enter_phase(PHASE_SHUTDOWN);

    if (loc.file && loc.line) {
	Message(M_FATAL, "config error (%s, %s:%d): ",facility,loc.file,
		loc.line);
    } else if (!loc.file && loc.line) {
	Message(M_FATAL, "config error (%s, line %d): ",facility,loc.line);
    } else {
	Message(M_FATAL, "config error (%s): ",facility);
    }
    
    vMessage(M_FATAL,message,args);
    va_end(args);
    exit(current_phase);
}

/* Take a list of log closures and merge them */
struct loglist {
    struct log_if *l;
    struct loglist *next;
};

static void log_vmulti(void *sst, int class, char *message, va_list args)
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

static void log_multi(void *st, int priority, char *message, ...)
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

static string_t months[]={
    "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};

static void logfile_vlog(void *sst, int class, char *message, va_list args)
{
    struct logfile *st=sst;
    time_t t;
    struct tm *tm;

    if (secnet_is_daemon) {
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

static void logfile_log(void *state, int priority, char *message, ...)
{
    va_list ap;

    va_start(ap,message);
    logfile_vlog(state,priority,message,ap);
    va_end(ap);
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
    { "error", M_ERROR },
    { "security", M_SECURITY },
    { "fatal", M_FATAL },
    { "default", M_WARNING|M_ERROR|M_SECURITY|M_FATAL },
    { "verbose", M_INFO|M_NOTICE|M_WARNING|M_ERROR|M_SECURITY|M_FATAL },
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
    st->f=stderr;

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
    case M_ERROR: return LOG_ERR;
    case M_SECURITY: return LOG_CRIT;
    case M_FATAL: return LOG_EMERG;
    default: return LOG_NOTICE;
    }
}
    
static void syslog_vlog(void *sst, int class, char *message,
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

static void syslog_log(void *sst, int priority, char *message, ...)
{
    va_list ap;

    va_start(ap,message);
    syslog_vlog(sst,priority,message,ap);
    va_end(ap);
}

static struct flagstr syslog_facility_table[]={
    { "authpriv", LOG_AUTHPRIV },
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

char *safe_strdup(char *s, char *message)
{
    char *d;
    d=strdup(s);
    if (!d) {
	fatal_perror(message);
    }
    return d;
}

void *safe_malloc(size_t size, char *message)
{
    void *r;
    r=malloc(size);
    if (!r) {
	fatal_perror(message);
    }
    return r;
}

/* Convert a buffer into its MP_INT representation */
void read_mpbin(MP_INT *a, uint8_t *bin, int binsize)
{
    char *buff;
    int i;

    buff=safe_malloc(binsize*2 + 1,"read_mpbin");

    for (i=0; i<binsize; i++) {
	buff[i*2]=hexdigits[(bin[i] & 0xf0) >> 4];
	buff[i*2+1]=hexdigits[(bin[i] & 0xf)];
    }
    buff[binsize*2]=0;

    mpz_set_str(a, buff, 16);
    free(buff);
}

/* Convert a MP_INT into a hex string */
char *write_mpstring(MP_INT *a)
{
    char *buff;

    buff=safe_malloc(mpz_sizeinbase(a,16)+2,"write_mpstring");
    mpz_get_str(buff, 16, a);
    return buff;
}

static uint8_t hexval(uint8_t c)
{
    switch (c) {
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'a': return 10;
    case 'A': return 10;
    case 'b': return 11;
    case 'B': return 11;
    case 'c': return 12;
    case 'C': return 12;
    case 'd': return 13;
    case 'D': return 13;
    case 'e': return 14;
    case 'E': return 14;
    case 'f': return 15;
    case 'F': return 15;
    }
    return -1;
}

/* Convert a MP_INT into a buffer; return length; truncate if necessary */
uint32_t write_mpbin(MP_INT *a, uint8_t *buffer, uint32_t buflen)
{
    char *hb;
    int i,j,l;
    
    if (buflen==0) return 0;
    hb=write_mpstring(a);
    
    l=strlen(hb);
    i=0; j=0;
    if (l&1) {
	/* The number starts with a half-byte */
	buffer[i++]=hexval(hb[j++]);
    }
    for (; hb[j] && i<buflen; i++) {
	buffer[i]=(hexval(hb[j])<<4)|hexval(hb[j+1]);
	j+=2;
    }
    free(hb);
    return i;
}

bool_t subnet_match(struct subnet *s, uint32_t address)
{
    return (s->prefix==(address&s->mask));
}

bool_t subnet_matches_list(struct subnet_list *list, uint32_t address)
{
    uint32_t i;
    for (i=0; i<list->entries; i++) {
	if (list->list[i].prefix == (address&list->list[i].mask)) return True;
    }
    return False;
}

bool_t subnets_intersect(struct subnet a, struct subnet b)
{
    uint32_t mask=a.mask&b.mask;
    return ((a.prefix&mask)==(b.prefix&mask));
}

bool_t subnet_intersects_with_list(struct subnet a, struct subnet_list *b)
{
    uint32_t i;

    for (i=0; i<b->entries; i++) {
	if (subnets_intersect(a,b->list[i])) return True;
    }
    return False;
}

bool_t subnet_lists_intersect(struct subnet_list *a, struct subnet_list *b)
{
    uint32_t i;
    for (i=0; i<a->entries; i++) {
	if (subnet_intersects_with_list(a->list[i],b)) return True;
    }
    return False;
}

/* The string buffer must be at least 16 bytes long */
string_t ipaddr_to_string(uint32_t addr)
{
    uint8_t a,b,c,d;
    string_t s;

    s=safe_malloc(16,"ipaddr_to_string");
    a=addr>>24;
    b=addr>>16;
    c=addr>>8;
    d=addr;
    snprintf(s, 16, "%d.%d.%d.%d", a, b, c, d);
    return s;
}

string_t subnet_to_string(struct subnet *sn)
{
    uint32_t mask=sn->mask, addr=sn->prefix;
    uint8_t a,b,c,d;
    string_t s;
    int i;

    s=safe_malloc(19,"subnet_to_string");
    a=addr>>24;
    b=addr>>16;
    c=addr>>8;
    d=addr;
    for (i=0; mask; i++) {
	mask=(mask<<1);
    }
    if (i!=sn->len) {
	fatal("subnet_to_string: invalid subnet structure!\n");
    }
    snprintf(s, 19, "%d.%d.%d.%d/%d", a, b, c, d, sn->len);
    return s;
}

int sys_cmd(const char *path, char *arg, ...)
{
    va_list ap;
    int rv;
    pid_t c;

    va_start(ap,arg);
    c=fork();
    if (c) {
	/* Parent -> wait for child */
	waitpid(c,&rv,0);
    } else if (c==0) {
	char *args[100];
	int i;
	/* Child -> exec command */
	args[0]=arg;
	i=1;
	while ((args[i++]=va_arg(ap,char *)));
	execvp(path,args);
	exit(1);
    } else {
	/* Error */
	fatal_perror("sys_cmd(%s,%s,...)");
    }

    va_end(ap);
    return rv;
}

static char *phases[NR_PHASES]={
    "PHASE_INIT",
    "PHASE_GETOPTS",
    "PHASE_READCONFIG",
    "PHASE_SETUP",
    "PHASE_GETRESOURCES",
    "PHASE_DROPPRIV",
    "PHASE_RUN",
    "PHASE_SHUTDOWN"
};

void enter_phase(uint32_t new_phase)
{
    struct phase_hook *i;

    if (hooks[new_phase])
	Message(M_DEBUG_PHASE,"Running hooks for %s...\n", phases[new_phase]);
    current_phase=new_phase;

    for (i=hooks[new_phase]; i; i=i->next)
	i->fn(i->state, new_phase);
    Message(M_DEBUG_PHASE,"Now in %s\n",phases[new_phase]);
}

bool_t add_hook(uint32_t phase, hook_fn *fn, void *state)
{
    struct phase_hook *h;

    h=safe_malloc(sizeof(*h),"add_hook");
    h->fn=fn;
    h->state=state;
    h->next=hooks[phase];
    hooks[phase]=h;
    return True;
}

bool_t remove_hook(uint32_t phase, hook_fn *fn, void *state)
{
    fatal("remove_hook: not implemented\n");

    return False;
}

void log(struct log_if *lf, int priority, char *message, ...)
{
    va_list ap;
    
    va_start(ap,message);
    lf->vlog(lf->st,priority,message,ap);
    va_end(ap);
}

struct buffer {
    closure_t cl;
    struct buffer_if ops;
};

void buffer_assert_free(struct buffer_if *buffer, string_t file, uint32_t line)
{
    if (!buffer->free) {
	fatal("BUF_ASSERT_FREE, %s line %d, owned by %s\n",
	      file,line,buffer->owner);
    }
}

void buffer_assert_used(struct buffer_if *buffer, string_t file, uint32_t line)
{
    if (buffer->free) {
	fatal("BUF_ASSERT_USED, %s line %d, last owned by %s\n",
	      file,line,buffer->owner);
    }
}

void buffer_init(struct buffer_if *buffer, uint32_t max_start_pad)
{
    buffer->start=buffer->base+max_start_pad;
    buffer->size=0;
}

void *buf_append(struct buffer_if *buf, uint32_t amount) {
    void *p;
    p=buf->start + buf->size;
    buf->size+=amount;
    return p;
}

void *buf_prepend(struct buffer_if *buf, uint32_t amount) {
    buf->size+=amount;
    return buf->start-=amount;
}

void *buf_unappend(struct buffer_if *buf, uint32_t amount) {
    if (buf->size < amount) return 0;
    return buf->start+(buf->size-=amount);
}

void *buf_unprepend(struct buffer_if *buf, uint32_t amount) {
    void *p;
    p=buf->start;
    buf->start+=amount;
    buf->size-=amount;
    return p;
}

/* Append a two-byte length and the string to the buffer. Length is in
   network byte order. */
void buf_append_string(struct buffer_if *buf, string_t s)
{
    uint16_t len;

    len=strlen(s);
    buf_append_uint16(buf,len);
    memcpy(buf_append(buf,len),s,len);
}

void buffer_new(struct buffer_if *buf, uint32_t len)
{
    buf->free=True;
    buf->owner=NULL;
    buf->flags=0;
    buf->loc.file=NULL;
    buf->loc.line=0;
    buf->size=0;
    buf->len=len;
    buf->start=NULL;
    buf->base=safe_malloc(len,"buffer_new");
}

static list_t *buffer_apply(closure_t *self, struct cloc loc, dict_t *context,
			    list_t *args)
{
    struct buffer *st;
    item_t *item;
    dict_t *dict;
    bool_t lockdown=False;
    uint32_t len=DEFAULT_BUFFER_SIZE;
    
    st=safe_malloc(sizeof(*st),"buffer_apply");
    st->cl.description="buffer";
    st->cl.type=CL_BUFFER;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;

    /* First argument, if present, is buffer length */
    item=list_elem(args,0);
    if (item) {
	if (item->type!=t_number) {
	    cfgfatal(st->ops.loc,"buffer","first parameter must be a "
		     "number (buffer size)\n");
	}
	len=item->data.number;
	if (len<MIN_BUFFER_SIZE) {
	    cfgfatal(st->ops.loc,"buffer","ludicrously small buffer size\n");
	}
	if (len>MAX_BUFFER_SIZE) {
	    cfgfatal(st->ops.loc,"buffer","ludicrously large buffer size\n");
	}
    }
    /* Second argument, if present, is a dictionary */
    item=list_elem(args,1);
    if (item) {
	if (item->type!=t_dict) {
	    cfgfatal(st->ops.loc,"buffer","second parameter must be a "
		     "dictionary\n");
	}
	dict=item->data.dict;
	lockdown=dict_read_bool(dict,"lockdown",False,"buffer",st->ops.loc,
				False);
    }

    buffer_new(&st->ops,len);
    if (lockdown) {
	/* XXX mlock the buffer if possible */
    }
    
    return new_closure(&st->cl);
}

init_module util_module;
void util_module(dict_t *dict)
{
    add_closure(dict,"logfile",logfile_apply);
    add_closure(dict,"syslog",syslog_apply);
    add_closure(dict,"sysbuffer",buffer_apply);
}
