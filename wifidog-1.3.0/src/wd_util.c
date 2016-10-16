/* vim: set et sw=4 sts=4 ts=4 : */
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

/**
  @file wd_util.c
  @brief Misc utility functions
  @author Copyright (C) 2015 Alexandre Carmel-Veilleux <acv@miniguru.ca>
 */

#include "common.h"

#include "gateway.h"
#include "commandline.h"
#include "client_list.h"
#include "safe.h"
#include "util.h"
#include "wd_util.h"
#include "debug.h"
#include "pstring.h"

#include "../config.h"
extern char* getConnErrSttStr();
extern char* getDpiStatisticsStr(u_int64_t tot_usec);
extern struct timeval dpi_begin;

t_inner_stt inner_stt = {0};

char* get_terminal_type(char* userAgent)
{
    if(!userAgent)                   return "Other";
    if(strstr(userAgent, "Windows")) return "PC";
    if(strstr(userAgent, "Ios"))     return "IOS";
    
    return "Android";
}

void mark_online()
{
    t_net_conn_mgmt_t* pOnline = get_net_conn_mgmt();
    if(pOnline->net_status != E_NET_CONN_ACTIVE)
    {
        pOnline->net_status = E_NET_CONN_ACTIVE;
        time(&pOnline->last_net_online_time);
    }
}

void mark_offline()
{
    t_net_conn_mgmt_t* pOnline = get_net_conn_mgmt();
    if(pOnline->net_status == E_NET_CONN_ACTIVE)
    {
        pOnline->net_status = E_NET_CONN_INACTIVE;
        pOnline->offline_times++;
        mark_auth_svrs_offline(true);
        mark_auth_agts_offline();
    }
}

bool is_online()
{
    if(E_NET_CONN_ACTIVE == get_net_conn_mgmt()->net_status)
      return TRUE;
    else
      return FALSE;  
}

void mark_auth_svrs_offline(bool isForce)
{
    t_auth_serv* svr=get_auth_server();
    for(; svr; svr=svr->next)
    {
        mark_auth_offline2(svr, isForce);
    }
}

void mark_auth_agts_offline()
{
    t_auth_serv* agt=get_auth_agent();
    for(; agt; agt=agt->next)
    {
        mark_auth_offline2(agt, false);
    }
}

void mark_auth_online2(t_auth_serv *auth_server, int sockfd)
{
    int before;
    int after;
    
    if(!auth_server) return;

	if(auth_server->authserv_http_port && auth_server->ctns_offline_cnt)
	{
		auth_server->ctns_offline_cnt = 0;
	}

    before = is_auth_online2(auth_server);
    if(E_AUTH_CONN_ACTIVE!=auth_server->status)
    {
        auth_server->socket_fd = sockfd;
        auth_server->echo_cnt = 0;
        auth_server->status = E_AUTH_CONN_ACTIVE;
        time(&auth_server->last_online_time);
    }
    after = is_auth_online2(auth_server);

    if (before != after) {
        debug(LOG_WARNING, "target {%s}: [%s] (%s) status became %s", 
                auth_server->auth_server_mgmt?auth_server->auth_server_mgmt->name:"null", 
                auth_server->authserv_hostname, auth_server->authserv_hostip, 
                after ? "ONLINE":"OFFLINE");
    }

    /* If auth server is online it means we're definately online */
    mark_online();
}

void mark_auth_offline2(t_auth_serv *auth_server, bool isForce)
{
    int before;
    int after;
    time_t tm;
    
    if(!auth_server) return;
    
    before = is_auth_online2(auth_server);
    if(E_AUTH_CONN_INACTIVE!=auth_server->status)
    {
        time(&tm);
        if(!isForce && auth_server->authserv_http_port)
        {
            auth_server->ctns_offline_cnt_sum++;
            auth_server->ctns_offline_cnt++;
            if(auth_server->ctns_offline_cnt < MAX_HTTP_CONTINUOUS_OFFLINE_CNT)
            {
                auth_server->last_ctns_offline_time[auth_server->ctns_offline_cnt-1] = tm;
                return;
            }
            if(auth_server->ctns_offline_cnt == MAX_HTTP_CONTINUOUS_OFFLINE_CNT)
                auth_server->last_ctns_offline_time[MAX_HTTP_CONTINUOUS_OFFLINE_CNT-1] = tm;
        }
        auth_server->socket_fd = -1;
        auth_server->status = E_AUTH_CONN_INACTIVE;
        auth_server->last_offline_time = tm;
        auth_server->offline_cnt++;
    }
    after = is_auth_online2(auth_server);

    if (before != after) {
        debug(LOG_WARNING, "target {%s}: [%s] (%s) status became %s", 
                auth_server->auth_server_mgmt?auth_server->auth_server_mgmt->name:"null", 
                auth_server->authserv_hostname, auth_server->authserv_hostip, 
                after ? "ONLINE":"OFFLINE");
    }
}

bool is_auth_srvs_online()
{
    t_auth_serv* svr=get_auth_server();
    for(; svr; svr=svr->next)
    {
        if(is_auth_online2(svr))
        {
            return TRUE;
        }
    }

    return FALSE;
}

bool is_auth_agts_online()
{
    t_auth_serv* agt=get_auth_agent();
    for(; agt; agt=agt->next)
    {
        if(is_auth_online2(agt))
        {
            return TRUE;
        }
    }

    return FALSE;
}

t_auth_serv* find_auth_agt_by_socket(int sockfd)
{
    t_auth_serv* agt=get_auth_agent();
    for(; agt; agt=agt->next)
    {
        if(sockfd == agt->socket_fd)
        {
            return agt;
        }
    }

    return NULL;
}

bool is_auth_online2(t_auth_serv *auth_server)
{
    if(!auth_server) return FALSE;
    
    if (auth_server->status == E_AUTH_CONN_INACTIVE)
    {
        /* Auth is offline */
        return FALSE;
    } 
    else
    {
        /* Auth is probably online */
        return TRUE;
    }
}

extern int RunRhyDpi;
/* @return A string containing human-readable status text. MUST BE free()d by caller */
char* get_status_text()
{
    pstr_t *pstr = pstr_new2(4*MAX_BUF);  //estimate the need of mem space according MAX_CLIENTMAXNUM, approxmately 120 bytes per client.
    char buf[MAX_GENERAL_LEN*2]={0};
    char buf1[MAX_GENERAL_LEN]={0};
    char buf2[MAX_GENERAL_LEN]={0};
    char buf3[MAX_GENERAL_LEN]={0};
    T_CONFIG *config;
    t_auth_serv *auth_server;
    t_client *sublist, *current;
    unsigned int cts_cnt;
    int count;
    int curcount;
    t_trusted_mac *p;
    char DlStr[MAX_GENERAL_LEN]={0};
    char UlStr[MAX_GENERAL_LEN]={0};

    time_t uptime = 0;
    unsigned int days = 0, hours = 0, minutes = 0, seconds = 0;
    char status[MAX_TEMP_BUFFER_SIZE]={0};
    
    snprintf(status, sizeof(status)-1, "%s version: %s\n", config_get_config()->company, config_get_config()->version);
    pstr_cat(pstr, status);
    
    uptime = time(NULL) - started_time;
    days = (unsigned int)uptime / (24 * 60 * 60);
    uptime -= days * (24 * 60 * 60);
    hours = (unsigned int)uptime / (60 * 60);
    uptime -= hours * (60 * 60);
    minutes = (unsigned int)uptime / 60;
    uptime -= minutes * 60;
    seconds = (unsigned int)uptime;
    
    pstr_append_sprintf(pstr, "Uptime: %ud %uh %um %us\n", days, hours, minutes, seconds);
    pstr_cat(pstr, "Has been restarted: ");
    
    if (restart_orig_pid) {
        pstr_append_sprintf(pstr, "yes (from PID %d)\n", restart_orig_pid);
    } else {
        pstr_cat(pstr, "no\n");
    }

    pstr_append_sprintf(pstr, "Dpi feature: %s, subswitch: %d, bpf: %s\n", 
                        config_get_config()->dpi_flag ? "started" : "stopped", RunRhyDpi,
                        config_get_config()->dpi_bpf);
                        
    pstr_append_sprintf(pstr, "\nClients login sessions: %llu, logout sessions: %llu, logout unauthenticated: %llu, excute fail:%llu\n", 
                              inner_stt.loginCnt, inner_stt.logoutCnt, inner_stt.logoutUnAuthened, inner_stt.logoutExcuteFail);

    LOCK_CLIENT_LIST();
    count = client_list_dup(&sublist);
    UNLOCK_CLIENT_LIST();

    current = sublist;

    pstr_append_sprintf(pstr, "%d clients " "connected.\n", count);
    pstr_append_sprintf(pstr, 
        "ClientNo.  IP               MAC                Phone       Token RecordId   DL(pkts/bytes)        UL(pkts/bytes)       \n");

    curcount = 0;
    while (curcount < count && current != NULL) {
        memset(DlStr, 0, sizeof(DlStr));
        memset(UlStr, 0, sizeof(UlStr));
        snprintf(DlStr, sizeof(DlStr)-1, "%llu/%llu", current->counters.inComingPkt, current->counters.inComingByt);
        snprintf(UlStr, sizeof(UlStr)-1, "%llu/%llu", current->counters.outGoingPkt, current->counters.outGoingByt);
        pstr_append_sprintf(pstr, "%-10llu %-16s %-18s %-11s %-5s %-10s %-21s %-21s\n", 
            current->id, current->ip, current->mac, current->phone, current->token, current->record_id,
            DlStr, UlStr);
        curcount++;
        current = current->next;
    }
    client_list_destroy(sublist);

    config = config_get_config();
    if (config->trustedmaclist != NULL) {
        pstr_cat(pstr, "\nTrusted MAC addresses:\n");

        for (p = config->trustedmaclist; p != NULL; p = p->next) {
            pstr_append_sprintf(pstr, "  %s\n", p->mac);
        }
    }

    LOCK_CONFIG();
    t_net_conn_mgmt_t* pNetConnMgmt = get_net_conn_mgmt();
    pstr_append_sprintf(pstr, "\nInternet Connectivity: [%s, LastOn:%.24s, LastOff:%.24s, OffTimesEver:%u]\n", 
                      net_conn_state2str(pNetConnMgmt->net_status), 
                      ctime_r(&pNetConnMgmt->last_net_online_time, buf1), ctime_r(&pNetConnMgmt->last_net_offline_time, buf2),
                      pNetConnMgmt->offline_times);

    pstr_cat(pstr, "\nAuthentication servers:\n");
    for (auth_server = get_auth_server(); auth_server != NULL; auth_server = auth_server->next) {
        for(cts_cnt=0; cts_cnt < auth_server->ctns_offline_cnt && cts_cnt < MAX_HTTP_CONTINUOUS_OFFLINE_CNT; cts_cnt++)
        {
            snprintf(buf+strlen(buf), sizeof(buf)-strlen(buf)-1, "\n\t\t\t\t\t\t[LastBroke%d:%.24s]", 
                cts_cnt+1, ctime_r(&auth_server->last_ctns_offline_time[cts_cnt], buf1));
        }
        pstr_append_sprintf(pstr, "  Host: %s (%s:%d) [%s, LastOn:%.24s, LastOff:%.24s, OffTimes:%u]\n"
            "\t\t\t\t\t\t[SumBrokeTimes:%u, CtnsBrokeTimes:%u]%s\n",
            auth_server->authserv_hostname, auth_server->last_ip, auth_server->authserv_http_port, 
            auth_conn_state2str(auth_server->status), 
            ctime_r(&auth_server->last_online_time, buf1), ctime_r(&auth_server->last_offline_time, buf2),
            auth_server->offline_cnt, 
            auth_server->ctns_offline_cnt_sum, auth_server->ctns_offline_cnt, buf);
    }

    pstr_cat(pstr, "\nAuthentication agents:\n");
    for (auth_server = get_auth_agent(); auth_server != NULL; auth_server = auth_server->next) {
        pstr_append_sprintf(pstr, "  Host: %s (%s:%d) [%s, LastOn:%.24s, LastOff:%.24s, OffTimes:%u]\n"
            "\t\t\t\t\t\t[EchoTimes:%u, LastEcho:%.24s]\n", 
            auth_server->authserv_hostname, auth_server->last_ip, auth_server->authagent_tcp_port, 
            auth_conn_state2str(auth_server->status),
            ctime_r(&auth_server->last_online_time, buf1), ctime_r(&auth_server->last_offline_time, buf2),
            auth_server->offline_cnt, 
            auth_server->echo_cnt, ctime_r(&auth_server->last_echo_time, buf3));
    }
    UNLOCK_CONFIG();

    return pstr_to_string(pstr);
}

char* get_statistics_text()
{
    pstr_t *pstr = pstr_new();

    t_client_list* pList = client_get_allocated_list();
    pstr_append_sprintf(pstr, "Running   clients:%3u, Allocated times:%llu, Free times:%llu\n", 
                        pList->eleNum, pList->allocCnt, pList->freeCnt);

    pList = client_get_free_list();
    pstr_append_sprintf(pstr, "Available clients:%3u, Allocated times:%llu, Free times:%llu\n", 
                        pList->eleNum, pList->allocCnt, pList->freeCnt);

    pstr_append_sprintf(pstr, "Iptables update times:%llu, Error times:%llu\n", 
                        inner_stt.iptblsUdpCnt, inner_stt.iptblsUpdErr);
                        
    pstr_append_sprintf(pstr, "Login:%llu [Server:%llu, Agent:%llu, Cmdline:%llu, offLine Server:%llu, offLine Agent:%llu]\n", 
                        inner_stt.loginCnt, inner_stt.loginByAuthServer, inner_stt.loginByAuthAgent,
                        inner_stt.loginByCmdLine, inner_stt.loginByNoServer, inner_stt.loginByNoAgent);
                        
    pstr_append_sprintf(pstr, "Logout:%llu [Validate:%llu, Server:%llu, Terminal:%llu, Cmdline:%llu, Timedout:%llu] ExcuteFail:%llu\n", 
                        inner_stt.logoutCnt, inner_stt.logoutValidateFail, inner_stt.logoutByAuthServer, 
                        inner_stt.logoutByTerminal, inner_stt.logoutByCmdLine, inner_stt.logoutBytimedOut, inner_stt.logoutExcuteFail);
                        
    pstr_append_sprintf(pstr, "Logout UnAuthenticated:%llu\n", inner_stt.logoutUnAuthened);
                        
    pstr_append_sprintf(pstr, "Notify server success:%llu, fail:%llu\n", 
                        inner_stt.notifyAuthServerSuccess, inner_stt.notifyAuthServerFail);

    pstr_append_sprintf(pstr, "%s", client_show_all_list());
    pstr_append_sprintf(pstr, "%s", getConnErrSttStr());
    return pstr_to_string(pstr);
}

char* get_dpi_stt_text()
{
	struct timeval time_now;
	u_int64_t tot_usec;

    pstr_t *pstr = pstr_new2(MAX_BUF*3);
	gettimeofday(&time_now, NULL);
	tot_usec = time_now.tv_sec*1000000 + time_now.tv_usec - (dpi_begin.tv_sec*1000000 + dpi_begin.tv_usec);

    pstr_append_sprintf(pstr, "%s", getDpiStatisticsStr(tot_usec));
    return pstr_to_string(pstr);
}

