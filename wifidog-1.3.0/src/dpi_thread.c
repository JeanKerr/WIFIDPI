/* vim: set sw=4 ts=4 sts=4 et : */
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

/* $Id$ */
/** @file portal_thread.c
    @brief Periodically checks in with the central portal server checks on 
    the portal server to see if local portal version is up-to-date.
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#include "common.h"
#include "debug.h"
#include "dpi_thread.h"

extern int dpi_main(int argc, char **argv);
extern int RunRhyDpi;

void thread_comm_dpi(void *arg)
{
    int argc=8;
    char* argv[8]={"RhyDpi", "-i", NULL/*eth0*/, "-f", NULL/*"udp port 53"*/, "-w", "/dev/null", "-q"};
    T_DPI_PARAM* DpiParam = arg;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;

    RunRhyDpi = DpiParam->dpiFlag;
    while (1) {
        if(DpiParam->dpiFlag && RunRhyDpi)
        {
            argv[2]=DpiParam->portName;
            argv[4]=DpiParam->bpfFilter;
            argv[6]=DpiParam->logPath;
            debug(LOG_INFO, "%s %s:  %s %s %s %s %s %s %s", 
                           RunRhyDpi ? "Start" : "Stop", 
                           argv[0], argv[1], argv[2], argv[3], 
                           argv[4], argv[5], argv[6], argv[7]);
            dpi_main(argc, argv);
        }
        /* Sleep for 10 seconds... */
        timeout.tv_sec = time(NULL) + 60;
        timeout.tv_nsec = 0;

        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);

        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);
    }
}





