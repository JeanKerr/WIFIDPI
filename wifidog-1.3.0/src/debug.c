/* vim: set et ts=4 sts=4 sw=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/** @file debug.c
    @brief Debug output routines
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#if (defined __x86_64__)
#include <execinfo.h>
#endif

#include "debug.h"

debugconf_t debugconf = {
    .debuglevel = LOG_INFO,
    .log_stderr = 1,
    .log_syslog = 0,
    .syslog_facility = 0
};

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/** @internal
Do not use directly, use the debug macro */
void _debug(const char *filename, int line, int level, const char *format, ...)
{
    if (debugconf.debuglevel >= level)
    {
        char buf[30]={0};
        va_list vlist;
        time_t ts;
        sigset_t block_chld;
        
        time(&ts);

        sigemptyset(&block_chld);
        sigaddset(&block_chld, SIGCHLD);
        sigprocmask(SIG_BLOCK, &block_chld, NULL);

        if (level <= LOG_WARNING || debugconf.log_stderr) {
            pthread_mutex_lock(&log_mutex);
            fprintf(stderr, "[%d%.24s][%u:%x](%s:%d) ", level, ctime_r(&ts, buf), getpid(), (unsigned int)pthread_self(), filename, line);
            va_start(vlist, format);
            vfprintf(stderr, format, vlist);
            va_end(vlist);
            fputc('\n', stderr);
            pthread_mutex_unlock(&log_mutex);
        } 
        #if 0
        else if (debugconf.log_stderr) {
            fprintf(stderr, "[%d][%.24s][%u](%s:%d) ", level, ctime_r(&ts, buf), getpid(), filename, line);
            va_start(vlist, format);
            vfprintf(stderr, format, vlist);
            va_end(vlist);
            fputc('\n', stderr);
        }
        #endif
        if (debugconf.log_syslog && level <= LOG_INFO) {
            openlog("rhy", LOG_PID, debugconf.syslog_facility);
            va_start(vlist, format);
            vsyslog(level, format, vlist);
            va_end(vlist);
            closelog();
        }
        
        sigprocmask(SIG_UNBLOCK, &block_chld, NULL);
    }
}

#define BACKTRACE_SIZE 256

/* dump the stack of the calling core */
void _dump_stack(void)
{
#if (defined __x86_64__)
	void *func[BACKTRACE_SIZE];
	char **symb = NULL;
	int size;

	size = backtrace(func, BACKTRACE_SIZE);
	symb = backtrace_symbols(func, size);

	if (symb == NULL)
		return;

	while (size > 0) {
		debug(LOG_ERR,
			"%d: [%s]\n", size, symb[size - 1]);
		size --;
	}

	free(symb);
#endif

}

/* not implemented in this environment */
void _dump_registers(void)
{
	return;
}

/* call abort(), it will generate a coredump if enabled */
void _panic(const char *funcname, const int line, const char *format, ...)
{
	debug(LOG_EMERG, "PANIC in %s(), line:%d\n", funcname, line);
	_dump_stack();
	_dump_registers();
	abort();
}

/*
 * Like _rhy_panic this terminates the application. However, no traceback is
 * provided and no core-dump is generated.
 */
void __exit(int exit_code, const char *funcname, const int line)
{
	debug(LOG_ALERT, "exit %d in %s(), line:%d\n", exit_code, funcname, line);
	_dump_stack();
	_dump_registers();
	exit(exit_code);
}

