/* Hacky parallelism; Ian Jackson */

#define _GNU_SOURCE

#include "secnet.h"
#include "util.h"
#include "hackypar.h"

#ifdef HACKY_PARALLEL

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <sys/wait.h>

#define HASHSIZE 16
#define CACHESIZE 16

typedef enum { hp_idle, hp_compute, hp_deferring, hp_fail } HPState;

static HPState state;
static pid_t child;

static void checkchild(void) {
  int r, status;
  
  if (!child) return;

  r= waitpid(child,&status,WNOHANG); if (!r) return;
  if (r==-1) {
    Message(M_ERR,"hacky_par: waitpid: %s\n",strerror(errno));
    return;
  }
  child= 0;
  
  if (WIFSIGNALED(status)) {
    Message(M_ERR,"hacky_par: signaled! %s\n",strsignal(WTERMSIG(status)));
  } else if (!WIFEXITED(status)) {
    Message(M_ERR,"hacky_par: unexpected status! %d\n", r);
  }
}

static HPState start(void) {
  assert(!child);

  child= fork();
  if (child == -1) {
    Message(M_ERR,"hacky_par: fork failed: %s\n",strerror(errno));
    return hp_fail;
  }

  if (!child) { /* we are the child */
    return hp_compute;
  }

  Message(M_INFO,"hacky_par: started, punting\n");
  return hp_deferring;
}

int hacky_par_start_failnow(void) {
  state= hp_idle;
  checkchild();
  if (child) {
    state= hp_deferring;
    Message(M_INFO,"hacky_par: busy, punting\n");
    return 1;
  }
  return 0;
}

int hacky_par_mid_failnow(void) {
  state= start();
  return state != hp_compute;
}

bool_t (*packy_par_gen)(struct site *st);

void hacky_par_end(int *ok,
		   uint32_t retries, uint32_t timeout,
		   bool_t (*send_msg)(struct site *st), struct site *st) {
  int i;
  
  switch (state) {
  case hp_deferring:
    assert(!*ok);
    *ok= 1;
    return;
  case hp_fail:
    assert(!*ok);
    return;
  case hp_idle:
    return;
  case hp_compute:
    if (!ok) {
      Message(M_ERR,"hacky_par: compute failed\n");
      _exit(2);
    }
    Message(M_INFO,"hacky_par: got result, sending\n");
    for (i=1; i<retries; i++) {
        sleep((timeout + 999)/1000);
	if (!send_msg(st)) {
	    Message(M_ERR,"hacky_par: retry failed\n");
	    _exit(1);
	}
    }
    _exit(0);
  }
}

#else /*!HACKY_PARALLEL*/

int hacky_par_start_failnow(void) { return 0; }
int hacky_par_mid_failnow(void) { return 0; }
void hacky_par_end(int *ok,
		   uint32_t retries, uint32_t timeout,
		   bool_t (*send_msg)(struct site *st), struct site *st) { }

#endif /*HACKY_PARALLEL...else*/
