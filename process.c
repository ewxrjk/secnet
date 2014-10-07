#define _GNU_SOURCE
#include "secnet.h"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <string.h>
#include "process.h"

/* Process handling - subprocesses, signals, etc. */

static bool_t signal_handling=False;
static sigset_t emptyset, fullset;
static sigset_t registered,pending;

struct child {
    pid_t pid;
    cstring_t desc;
    process_callback_fn *cb;
    void *cst;
    bool_t finished;
    struct child *next;
};

static struct child *children=NULL;

struct signotify {
    int signum;
    signal_notify_fn *notify;
    void *cst;
    struct signotify *next;
};

static struct signotify *sigs=NULL;

static int spw,spr; /* file descriptors for signal notification pipe */

/* Long-lived subprocesses can only be started once we've started
   signal processing so that we can catch SIGCHLD for them and report
   their exit status using the callback function.  We block SIGCHLD
   until signal processing has begun. */
pid_t makesubproc(process_entry_fn *entry, process_callback_fn *cb,
		 void *est, void *cst, cstring_t desc)
{
    struct child *c;
    pid_t p;

    NEW(c);
    c->desc=desc;
    c->cb=cb;
    c->cst=cst;

    if (!signal_handling) {
	fatal("makesubproc called before signal handling started");
    }
    p=fork();
    if (p==0) {
	/* Child process */
	afterfork();
	entry(est);
	abort();
    } else if (p==-1) {
	fatal_perror("makesubproc (%s): fork",desc);
    }
    c->pid=p;
    c->finished=False;
    c->next=children;
    children=c;
    return p;
}

static signal_notify_fn sigchld_handler;
static void sigchld_handler(void *st, int signum)
{
    struct child *i,*n,**p;
    struct work {
	pid_t pid;
	process_callback_fn *cb;
	void *cst;
	int status;
	struct work *next;
    };
    struct work *w=NULL, *nw;
    pid_t rv;
    int status;

    for (i=children; i; i=i->next) {
	rv=waitpid(i->pid,&status,WNOHANG);
	if (rv==-1) {
	    fatal_perror("sigchld_handler: waitpid");
	}
	if (rv==i->pid) {
	    i->finished=True;
	    
	    NEW(nw);
	    nw->pid=i->pid;
	    nw->cb=i->cb;
	    nw->cst=i->cst;
	    nw->status=status;
	    nw->next=w;
	    w=nw;
	}
    }

    /* Remove all the finished tasks from the list of children */
    for (i=children, p=&children; i; i=n) {
	n=i->next;
	if (i->finished) {
	    free(i);
	    *p=n;
	} else {
	    p=&i->next;
	}
    }

    /* Notify as appropriate, then free the list */
    while (w) {
	w->cb(w->cst,w->pid,w->status);
	nw=w;
	w=w->next;
	free(nw);
    }
}

int sys_cmd(const char *path, const char *arg, ...)
{
    va_list ap;
    int rv, rc;
    pid_t c;

    c=fork();
    if (c) {
	/* Parent -> wait for child */
	do {
	    rc = waitpid(c,&rv,0);
	} while(rc < 0 && errno == EINTR);
	if (rc < 0)
	    fatal_perror("sys_cmd: waitpid for %s", path);
	if (rc != c) /* OS has gone mad */
	    fatal("sys_cmd: waitpid for %s returned wrong process ID!",
		  path);
	if (rv) {
	    /* If the command failed report its exit status */
	    lg_exitstatus(0,"sys_cmd",0,M_ERR,rv,path);
	}
    } else if (c==0) {
	char *args[100];
	int i;
	/* Child -> exec command */
	/* Really we ought to strcpy() the arguments into the args array,
	   since the arguments are const char *.  Since we'll exit anyway
	   if the execvp() fails this seems somewhat pointless, and
	   increases the chance of the child process failing before it
	   gets to exec(). */
	afterfork();
	va_start(ap,arg);
	args[0]=(char *)arg; /* program name */
	i=1;
	while ((args[i++]=va_arg(ap,char *)));
	execvp(path,args);
	fprintf(stderr, "sys_cmd(%s,%s,...): %s\n", path, arg, strerror(errno));
	_exit(1);
    } else {
	/* Error */
	fatal_perror("sys_cmd(%s,%s,...)", path, arg);
    }

    return rv;
}

static beforepoll_fn signal_beforepoll;
static int signal_beforepoll(void *st, struct pollfd *fds, int *nfds_io,
			     int *timeout_io)
{
    BEFOREPOLL_WANT_FDS(1);
    fds[0].fd=spr;
    fds[0].events=POLLIN;
    return 0;
}

/* Bodge to work around Ubuntu's strict header files */
static void discard(int anything) {}

static afterpoll_fn signal_afterpoll;
static void signal_afterpoll(void *st, struct pollfd *fds, int nfds)
{
    uint8_t buf[16];
    struct signotify *n;
    sigset_t todo,old;

    if (nfds && (fds->revents & POLLIN)) {
	discard(read(spr,buf,16));
	                  /* We don't actually care what we read; as
			     long as there was at least one byte
			     (which there was) we'll pick up the
			     signals in the pending set */
	
	/* We reset 'pending' before processing any of the signals
	   that were pending so that we don't miss any signals that
	   are delivered partway-through processing (all we assume
	   about signal notification routines is that they handle all
	   the work available at their _start_ and only optionally any
	   work that arrives part-way through their execution). */
	sigprocmask(SIG_SETMASK,&fullset,&old);
	todo=pending;
	sigemptyset(&pending);
	sigprocmask(SIG_SETMASK,&old,NULL);
	
	for (n=sigs; n; n=n->next)
	    if (sigismember(&todo,n->signum))
		n->notify(n->cst,n->signum);
    }
}

void afterfork(void)
{
    struct signotify *n;
    sigset_t done;
    struct sigaction sa;

    clear_phase_hooks(PHASE_SHUTDOWN);
    /* Prevents calls to fatal() etc. in the child from running off
       and doing a lot of unhelpful things */

    sigemptyset(&done);
    for (n=sigs; n; n=n->next)
	if (!sigismember(&done,n->signum)) {
	    sigaddset(&done,n->signum);
	    sa.sa_handler=SIG_DFL;
	    sa.sa_mask=emptyset;
	    sa.sa_flags=0;
	    sigaction(n->signum,&sa,NULL);
	}

    sigemptyset(&emptyset);
    sigprocmask(SIG_SETMASK,&emptyset,NULL);
}

void childpersist_closefd_hook(void *fd_vp, uint32_t newphase)
{
    int *fd_p=fd_vp;
    int fd=*fd_p;
    if (fd<0) return;
    *fd_p=-1;
    setnonblock(fd); /* in case close() might block */
    close(fd); /* discard errors - we don't care, in the child */
}

static void signal_handler(int signum)
{
    int saved_errno;
    uint8_t thing=0;
    sigaddset(&pending,signum);
    /* XXX the write() may set errno, which can make the main program fail.
       However, signal handlers aren't allowed to modify anything which
       is not of type sig_atomic_t.  The world is broken. */
    /* I have decided to save and restore errno anyway; on most
       architectures on which secnet can run modifications to errno
       will be atomic, and it seems to be the lesser of the two
       evils. */
    saved_errno=errno;
    discard(write(spw,&thing,1));
                         /* We don't care if this fails (i.e. the pipe
			    is full) because the service routine will
			    spot the pending signal anyway */
    errno=saved_errno;
}

static void register_signal_handler(struct signotify *s)
{
    struct sigaction sa;
    int rv;

    if (!signal_handling) return;

    if (sigismember(&registered,s->signum)) return;
    sigaddset(&registered,s->signum);

    sa.sa_handler=signal_handler;
    sa.sa_mask=fullset;
    sa.sa_flags=0;
    rv=sigaction(s->signum,&sa,NULL);
    if (rv!=0) {
	fatal_perror("register_signal_handler: sigaction(%d)",s->signum);
    }
}

void request_signal_notification(int signum, signal_notify_fn *notify,
				 void *cst)
{
    struct signotify *s;
    sigset_t old;

    NEW(s);
    s->signum=signum;
    s->notify=notify;
    s->cst=cst;
    s->next=sigs;
    sigprocmask(SIG_SETMASK,&fullset,&old);
    sigs=s;
    register_signal_handler(s);
    sigprocmask(SIG_SETMASK,&old,NULL);
}

void start_signal_handling(void)
{
    int p[2];
    struct signotify *i;

    sigemptyset(&emptyset);
    sigfillset(&fullset);
    sigemptyset(&registered);
    sigemptyset(&pending);

    pipe_cloexec(p);
    spw=p[1];
    spr=p[0];
    setnonblock(spw);
    setnonblock(spr);

    register_for_poll(NULL,signal_beforepoll,signal_afterpoll,"signal");
    signal_handling=True;

    /* Register signal handlers for all the signals we're interested in */
    for (i=sigs; i; i=i->next) {
	register_signal_handler(i);
    }

    request_signal_notification(SIGCHLD,sigchld_handler,NULL);
}
