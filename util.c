/* $Log: util.c,v $
 * Revision 1.2  1996/04/14 16:34:36  sde1000
 * Added syslog support
 * mpbin/mpstring functions moved from dh.c
 *
 * Revision 1.1  1996/03/14 17:05:03  sde1000
 * Initial revision
 *
 */

#include "config.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <values.h>
#include <assert.h>
#include "util.h"
#include "secnet.h"

#define MIN_BUFFER_SIZE 64
#define DEFAULT_BUFFER_SIZE 4096
#define MAX_BUFFER_SIZE 131072

static char *hexdigits="0123456789abcdef";

uint32_t message_level=M_WARNING|M_ERROR|M_FATAL;
uint32_t syslog_level=M_WARNING|M_ERROR|M_FATAL;
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
    if (class & message_level) {
	if (class&M_FATAL || class&M_ERROR || class&M_WARNING) {
	    dest=stderr;
	}
	vfprintf(dest,message,args);
    }
/* XXX do something about syslog output here */
#if 0
    /* Maybe send message to syslog */
    vsprintf(buff, message, args);
    /* XXX Send each line as a separate log entry */
    log(syslog_prio[level], buff);
#endif /* 0 */
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

bool_t subnet_match(struct subnet_list *list, uint32_t address)
{
    uint32_t i;
    for (i=0; i<list->entries; i++) {
	if (list->list[i].prefix == (address&list->list[i].mask)) return True;
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
    snprintf(s, 19, "%d.%d.%d.%d/%d", a, b, c, d, i);
    return s;
}

/* Take a list of log closures and merge them */
struct loglist {
    struct log_if *l;
    struct loglist *next;
};

static void log_vmulti(void *state, int priority, char *message, va_list args)
{
    struct loglist *st=state, *i;

    for (i=st; i; i=i->next) {
	i->l->vlog(i->l->st,priority,message,args);
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
	fatal("init_log: none of the items in the list are loggers");
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
    FILE *f;
};

static void logfile_vlog(void *state, int priority, char *message,
			 va_list args)
{
    struct logfile *st=state;

    vfprintf(st->f,message,args);
    fprintf(st->f,"\n");
}

static void logfile_log(void *state, int priority, char *message, ...)
{
    va_list ap;

    va_start(ap,message);
    logfile_vlog(state,priority,message,ap);
    va_end(ap);
}

static list_t *logfile_apply(closure_t *self, struct cloc loc, dict_t *context,
			     list_t *data)
{
    struct logfile *st;
    
    st=safe_malloc(sizeof(*st),"logfile_apply");
    st->cl.description="logfile";
    st->cl.type=CL_LOG;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.log=logfile_log;
    st->ops.vlog=logfile_vlog;
    st->f=stderr; /* XXX ignore args */

    return new_closure(&st->cl);
}
	
static char *phases[NR_PHASES]={
    "PHASE_INIT",
    "PHASE_GETOPTS",
    "PHASE_READCONFIG",
    "PHASE_SETUP",
    "PHASE_DROPPRIV",
    "PHASE_RUN",
    "PHASE_SHUTDOWN"
};

void enter_phase(uint32_t new_phase)
{
    struct phase_hook *i;

    Message(M_DEBUG_PHASE,"entering %s... ", phases[new_phase]);
    current_phase=new_phase;

    for (i=hooks[new_phase]; i; i=i->next)
	i->fn(i->state, new_phase);
    Message(M_DEBUG_PHASE,"now in %s\n",phases[new_phase]);
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
    *(uint16_t *)buf_append(buf,2)=htons(len);
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
    
    st=safe_malloc(sizeof(*st),"buffer_apply");
    st->cl.description="buffer";
    st->cl.type=CL_BUFFER;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.free=True;
    st->ops.owner=NULL;
    st->ops.flags=0;
    st->ops.loc=loc;
    st->ops.size=0;
    st->ops.len=DEFAULT_BUFFER_SIZE;
    st->ops.start=NULL;

    /* First argument, if present, is buffer length */
    item=list_elem(args,0);
    if (item) {
	if (item->type!=t_number) {
	    cfgfatal(st->ops.loc,"buffer","first parameter must be a "
		     "number (buffer size)\n");
	}
	st->ops.len=item->data.number;
	if (st->ops.len<MIN_BUFFER_SIZE) {
	    cfgfatal(st->ops.loc,"buffer","ludicrously small buffer size\n");
	}
	if (st->ops.len>MAX_BUFFER_SIZE) {
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

    st->ops.base=safe_malloc(st->ops.len,"buffer");
    if (lockdown) {
	Message(M_WARNING,"buffer: XXX lockdown\n");
    }
    
    return new_closure(&st->cl);
}

init_module util_module;
void util_module(dict_t *dict)
{
    add_closure(dict,"logfile",logfile_apply);
    add_closure(dict,"sysbuffer",buffer_apply);
}
