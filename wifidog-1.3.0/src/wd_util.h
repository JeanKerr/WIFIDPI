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

/** @file wd_util.h
  @brief Misc utility functions
  @author Copyright (C) 2015 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#ifndef _WD_UTIL_H_
#define _WD_UTIL_H_
#include "conf.h"

typedef struct _t_inner_stt
{
    unsigned long long iptblsUdpCnt;
    unsigned long long iptblsUpdErr;
    unsigned long long loginCnt;
    unsigned long long loginByAuthServer;
    unsigned long long loginByAuthAgent;
    unsigned long long loginByCmdLine;
    unsigned long long loginByNoServer;
    unsigned long long loginByNoAgent;
    unsigned long long logoutUnAuthened;
    unsigned long long logoutCnt;
    unsigned long long logoutExcuteFail;
    unsigned long long logoutValidateFail; /* validate failed in validation duration */
    unsigned long long logoutByAuthServer; /* auth server forcely kick out */
    unsigned long long logoutByTerminal;   /* phone terminal logout actively */
    unsigned long long logoutByCmdLine;    /* wdctl reset */
    unsigned long long logoutBytimedOut;   /* timed out client count */
    unsigned long long notifyAuthServerSuccess;   /* timed out client count */
    unsigned long long notifyAuthServerFail;   /* timed out client count */
} t_inner_stt;

/** @brief Client server this session. */
extern unsigned long long served_sessions;
extern unsigned long long logout_sessions;
extern t_inner_stt inner_stt;

/** @brief Analysis terminal type by user agent string */
char* get_terminal_type(char* userAgent);

/** @brief Sets hint that an online action (dns/connect/etc using WAN) succeeded */
void mark_online(void);

/** @brief Sets hint that an online action (dns/connect/etc using WAN) failed */
void mark_offline(void);

/** @brief Returns a guess (true or false) on whether we're online or not based on previous calls to mark_online and mark_offline */
bool is_online(void);

/** @brief Sets hint that an auth server online action succeeded */
void mark_auth_svrs_offline(bool isForce);

/** @brief Sets hint that an auth server online action failed */
void mark_auth_agts_offline(void);

/** @brief Sets hint that an auth server online action succeeded */
void mark_auth_online2(t_auth_serv *auth_server, int sockfd);

/** @brief Sets hint that an auth server online action failed */
void mark_auth_offline2(t_auth_serv *auth_server, bool isForce);

/** @brief Returns a result on whether auth server online */
bool is_auth_srvs_online();

/** @brief Returns a result on whether auth agent online */
bool is_auth_agts_online();

/** @brief Find auth agent by socket fd */
t_auth_serv* find_auth_agt_by_socket(int sockfd);

/** @brief Returns a result on whether auth agent/server online */
bool is_auth_online2(t_auth_serv *auth_server);

/** @brief Creates a human-readable paragraph of the status of process */
char* get_status_text(void);

/** @brief Creates a human-readable paragraph of the inner statistics of process */
char* get_statistics_text();

#endif /* _WD_UTIL_H_ */
