#ifndef process_h
#define process_h

#include <signal.h>
#include <sys/wait.h>

typedef void process_callback_fn(void *cst, pid_t pid, int status);
typedef void process_entry_fn(void *cst);
typedef void signal_notify_fn(void *cst, int signum);

extern pid_t makesubproc(process_entry_fn *entry, process_callback_fn *cb,
			void *est, void *cbst, string_t desc);

extern void request_signal_notification(int signum, signal_notify_fn *notify,
					void *cst);

#endif /* process_h */
