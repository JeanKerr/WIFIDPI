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
/** @file portal_thread.h
    @brief portal update thread
    @author Copyright (C) 2016 Jean.Kerr <coco.ke@ruhaoyi.com>
*/

#ifndef _PORTAL_THREAD_H_
#define _PORTAL_THREAD_H_

/** @brief Periodically checks on the portal server to see if local portal version is up-to-date. */
void thread_portal_update(void *arg);

/** @brief Listen on web connections . */
void thread_listen_web_connect(void *arg);



/*************add for version update*******************/
#define VERSION_UPDATE_DONE   0
#define VERSION_UPDATE_START  1

#define VERSION_UPDATE_LONG_STR_lEN  256
#define VERSION_UPDATE_SHORT_STR_lEN 64

#define VERSION_PATH "/tmp"
#define VERSION_NAME "lx-rhy.bin"
#define VERSION_SERVER_URL  "www.maixj.net:7961"
#define VERSION_SERVER_NAME VERSION_NAME /* "opewrt.txt" */



#define LOCK_VERSION_UPDATE() do { \
    debug(LOG_TRACE, "Locking version update@func:%s", __func__); \
    pthread_mutex_lock(&version_update_mutex); \
    debug(LOG_TRACE, "version update locked@func:%s", __func__); \
} while (0)

#define UNLOCK_VERSION_UPDATE() do { \
    debug(LOG_TRACE, "Unlocking version update@func:%s", __func__); \
    pthread_mutex_unlock(&version_update_mutex); \
    debug(LOG_TRACE, "version update unlocked@func:%s", __func__); \
} while (0)

typedef struct
{
    char taskID[VERSION_UPDATE_SHORT_STR_lEN];
    char url[VERSION_UPDATE_LONG_STR_lEN];
    char user[VERSION_UPDATE_SHORT_STR_lEN];
    char pwd[VERSION_UPDATE_SHORT_STR_lEN];
}VERSION_UPDATE_INFO;

void thread_version_update(void *arg);
bool version_update_start(char* msgData, unsigned int msgLen, tcp_request* r);
bool router_reset(char* msgData, unsigned int msgLen, tcp_request* r);


#endif
