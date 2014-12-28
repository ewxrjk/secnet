/*
 * This file is part of secnet.
 * See README for full list of copyright holders.
 *
 * secnet is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version d of the License, or
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

#ifndef process_h
#define process_h

#include <signal.h>
#include <sys/wait.h>

typedef void process_callback_fn(void *cst, pid_t pid, int status);
typedef void process_entry_fn(void *cst);
typedef void signal_notify_fn(void *cst, int signum);

extern pid_t makesubproc(process_entry_fn *entry, process_callback_fn *cb,
			void *est, void *cbst, cstring_t desc);

extern void request_signal_notification(int signum, signal_notify_fn *notify,
					void *cst);

#endif /* process_h */
