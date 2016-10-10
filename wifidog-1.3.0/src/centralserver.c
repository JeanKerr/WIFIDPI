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
/** @file centralserver.c
  @brief Functions to talk to the central server (auth/send stats/get rules/etc...)
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#include "common.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "httpd.h"
#include "safe.h"
#include "util.h"
#include "wd_util.h"
#include "auth.h"
#include "conf.h"
#include "debug.h"
#include "centralserver.h"
#include "firewall.h"
#include "cJSON.h"
#include "../config.h"

#include "simple_http.h"

#define USE_ALARM 0

#if USE_ALARM
void alarm_handler(int s)
{
    debug(LOG_TRACE, "Handler for SIGALARM called.");
}
#endif

/** Initiates a transaction with the auth server, either to authenticate or to
 * update the traffic counters at the server
@param authresponse Returns the information given by the central server 
@param request_type Use the REQUEST_TYPE_* defines in centralserver.h
@param ip IP adress of the client this request is related to
@param mac MAC adress of the client this request is related to
@param token Authentification token of the client
@param incoming Current counter of the client's total incoming traffic, in bytes 
@param outgoing Current counter of the client's total outgoing traffic, in bytes 
*/
t_authcode auth_server_request(t_authresponse* authresponse, E_REQUEST_TYPE request_type, const t_client *pClient)
{
    T_CONFIG *config = config_get_config();
    char buf[MAX_BUF]={0};
    t_auth_serv *auth_server = get_auth_server();
    char* pFound=NULL;
    char* res=NULL;
    char* JsonHead=NULL;
    char* ParseJsonOut=NULL;
    cJSON* pJson=NULL;
    int sockfd;
    char* mac;

    if(!authresponse || !pClient) return AUTH_ERROR;

    if(pClient->mac[0])
        mac = wd_convertmac(pClient->mac);
    else if(pClient->ip[0])
        mac = arp_get2(pClient->ip);
    else
        return AUTH_ERROR;
        
    /* Blanket default is error. */
    authresponse->authcode = AUTH_ERROR;

    sockfd = connect_auth_server();
    if (sockfd < 0) {
        free(mac);
        return authresponse->authcode;
    }

    if(E_REQUEST_TYPE_LOGOUT==request_type)
    {
        snprintf(buf, (sizeof(buf) - 1),
             "GET %s%s%suser_mac=%s&phone_tel=%s&pass_time=%llu&off_time=%llu&unit_type=%s&company=%d&internet_traffic=%llu&record_id=%s HTTP/%s\r\n"
             "User-Agent: %s %s\r\n"
             "Host: %s\r\n"
             "\r\n",
             auth_server->passive_path,
             auth_server->authserv_offline_script_path_fragment, auth_server->authserv_seperator,
             mac, pClient->phone, 
             pClient->pass_time, get_millisecond(), pClient->type,
             config->company_id, pClient->counters.inComingByt+pClient->counters.outGoingByt, pClient->record_id, 
             config->http_version,
             config->company, config->version, 
             ((auth_server->authserv_hostip!=NULL) ? auth_server->authserv_hostip:auth_server->last_ip));
    }
    else if(E_REQUEST_TYPE_LOGIN==request_type)
    {
        /* send login request */
        snprintf(buf, sizeof(buf) - 1,
             "GET %s%s%sphone_tel=%s&record_id=%s&user_mac=%s&identity_code=%s&company=%d HTTP/%s\r\n"
             "User-Agent: %s %s\r\n"
             "Host: %s\r\n"
             "\r\n",
             auth_server->passive_path, auth_server->authserv_login_script_path_fragment, auth_server->authserv_seperator,
             pClient->phone, pClient->record_id, mac, pClient->token, config->company_id,
             config->http_version,
             config->company, config->version, 
             (auth_server->authserv_hostip!=NULL) ? auth_server->authserv_hostip:auth_server->last_ip);
    }
    else
    {
        free(mac);
        return authresponse->authcode;
    }

    free(mac);
    
#ifdef USE_CYASSL
    if (auth_server->authserv_use_ssl) 
    {
        res = https_get(sockfd, buf, auth_server->authserv_hostname);
    }
    else
#endif
    {
        res = http_get2(sockfd, buf, '}');
    }

    if (NULL == res || NULL == (JsonHead=strchr(res, '{'))) 
    {
        debug(LOG_ERR, "Offline notify [%s] got unexpected response [%s] from server!", buf, res);
        if(res) 
            free(res);
        return authresponse->authcode;
    } 
    
    /* Utilize cJSON lib to parse version string, coco. *
     * Response contains placecode and version.         *
     * res string format example:                       *
     * "[\n {\n \"placecode\": \"200\",\n \"version\": \"1.0\",\n \"remark01\": \" \",\n \"remark02\": \" \",\n \"remark03\": \" \",\n \"remark04\": \" \",\n \"remark05\": \" \"\n }\n ]"; */
    
    debug(LOG_DEBUG, "auth_server_request get correct response:\n%s\n", JsonHead);
    pJson = cJSON_Parse(JsonHead);
    if (!pJson) 
    {
        debug(LOG_ERR, "auth_server_request[%s] JSON Parse Error before:\n%s\n", buf, cJSON_GetErrorPtr());
    }
    else
    {
        char jsonRetCode[HTTP_MAX_BUFFER_SIZE]={0};
        char jsonRetMsg[HTTP_MAX_BUFFER_SIZE]={0};
        char record_id[HTTP_MAX_BUFFER_SIZE]={0};
        char redirect_url[HTTP_MAX_BUFFER_SIZE]={0};
        ParseJsonOut = cJSON_Print(pJson);
        debug(LOG_DEBUG, "ParseJsonOut: %s", ParseJsonOut);
        pFound = cJSON_FindStrNStrValue(pJson, "code", jsonRetCode, sizeof(jsonRetCode)-1);
        if(pFound)
        {
            cJSON_FindStrNStrValue(pJson, "record_id", record_id, sizeof(record_id)-1);
            cJSON_FindStrNStrValue(pJson, "url", redirect_url, sizeof(redirect_url)-1);
        }
        pFound = cJSON_FindStrNStrValue(pJson, "msg", jsonRetMsg, sizeof(jsonRetMsg)-1);
        cJSON_Delete(pJson);
        free(ParseJsonOut);
        if((0==strncmp(jsonRetCode, "200", sizeof(jsonRetCode)-1))
        /* && (0==strncmp(jsonRetMsg, "SUCCESS", sizeof(jsonRetMsg)-1)) */)
        {
            authresponse->authcode = AUTH_ALLOWED;
        }
        else 
        {
            //if((0==strncmp(code, "201", sizeof(code)-1)) && (0==strncmp(msg, "PARAMETER ERROR", sizeof(msg)-1)))
            /* token error */
            //authresponse->authcode = AUTH_ERROR;
        }
    }

    free(res);
    return authresponse->authcode;
}

/* Tries really hard to connect to an auth server. Returns a file descriptor, -1 on error
 */
int connect_auth_server()
{
    int sockfd;

    LOCK_CONFIG();
    sockfd = _connect_auth_server(0);
    UNLOCK_CONFIG();

    if (sockfd < 0) {
        int got_authdown_ruleset = (NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1);
        if(got_authdown_ruleset)
            fw_set_authdown();
        debug(LOG_ALERT, "Failed to connect to any of the auth servers");

    } else {
        debug(LOG_INFO, "Connected to auth server");
    }
    return (sockfd);
}

/* Helper function called by connect_auth_server() to do the actual work including recursion
 * DO NOT CALL DIRECTLY
 @param level recursion level indicator must be 0 when not called by _connect_auth_server()
 */
int _connect_auth_server(int level)
{
    T_CONFIG *config = config_get_config();
    return _connect_auth(&config->auth_servers, level);
}

int _connect_auth_server2(int level)
{
    T_CONFIG *config = config_get_config();
    t_auth_serv *auth_server = NULL;
    t_popular_server *popular_server = NULL;
    struct in_addr *h_addr = NULL;
    int num_servers = 0;
    char *hostname = NULL;
    char ip[MAX_IP_ADDR_LEN]={0};
    struct sockaddr_in their_addr;
    int sockfd;

    /* If there are no auth servers, error out, from scan-build warning. */
    if (NULL == get_auth_server()) {
        debug(LOG_WARNING, "_connect_auth_server: no servers at all");
        return (-1);
    }

    /* XXX level starts out at 0 and gets incremented by every iterations. */
    level++;

    /*
     * Let's calculate the number of servers we have
     */
    for (auth_server = get_auth_server(); auth_server; auth_server = auth_server->next) {
        num_servers++;
    }
    debug(LOG_DEBUG, "Level %d: Calculated %d auth servers in list", level, num_servers);

    if (level > num_servers) {
        /*
         * We've called ourselves too many times
         * This means we've cycled through all the servers in the server list
         * at least once and none are accessible
         */
        return (-5);
    }

    /*
     * Let's resolve the hostname of the top server to an IP address
     */
    auth_server = get_auth_server();
    
    hostname = auth_server->authserv_hostname;
    if(auth_server->authserv_hostip)
    {
        debug(LOG_DEBUG, "Level %d: Direct auth server [%s]", level, auth_server->authserv_hostip);
        h_addr = wd_gethostbyipstring(auth_server->authserv_hostip);
        hostname = auth_server->authserv_hostip;
    }
    else if(NULL != hostname)
    {
        debug(LOG_DEBUG, "Level %d: Resolving auth server [%s]", level, hostname);
        h_addr = wd_gethostbyname(hostname);
    }

    if (!h_addr)
    {
        /*
         * DNS resolving it failed
         */
        debug(LOG_DEBUG, "Level %d: Resolving auth server [%s] failed", level, hostname);

        for (popular_server = config->popular_servers; popular_server; popular_server = popular_server->next) {
            debug(LOG_DEBUG, "Level %d: Resolving popular server [%s]", level, popular_server->hostname);
            h_addr = wd_gethostbyname(popular_server->hostname);
            if (h_addr) {
                debug(LOG_DEBUG, "Level %d: Resolving popular server [%s] succeeded = [%s]", level, popular_server->hostname,
                      inet_ntoa(*h_addr));
                break;
            } else {
                debug(LOG_DEBUG, "Level %d: Resolving popular server [%s] failed", level, popular_server->hostname);
            }
        }

        /* 
         * If we got any h_addr buffer for one of the popular servers, in other
         * words, if one of the popular servers resolved, we'll assume the DNS
         * works, otherwise we'll deal with net connection or DNS failure.
         */
        if (h_addr) 
        {
            free(h_addr);
            /*
             * Yes
             *
             * The auth server's DNS server is probably dead. Try the next auth server
             */
            debug(LOG_DEBUG, "Level %d: Marking auth server [%s] as bad and trying next if possible", level, hostname);
            if (auth_server->last_ip) {
                free(auth_server->last_ip);
                auth_server->last_ip = NULL;
            }
            mark_auth_offline2(auth_server, false);
            mark_auth_server_bad(auth_server);
            return _connect_auth_server(level);
        }
        else 
        {
            /*
             * No
             *
             * It's probably safe to assume that the internet connection is malfunctioning
             * and nothing we can do will make it work
             */
            debug(LOG_DEBUG, "Level %d: Failed to resolve auth server and all popular servers. "
                  "The internet connection is probably down", level);
            mark_offline();
            return (-6);
        }
    } 
    else
    {
        /*
         * DNS resolving was successful
         */
        mark_online();
        strncpy(ip, inet_ntoa(*h_addr), sizeof(ip)-1);
        debug(LOG_DEBUG, "Level %d: Resolving auth server [%s] succeeded = [%s]", level, hostname, ip);

        if (!auth_server->last_ip || strcmp(auth_server->last_ip, ip) != 0) 
        {
            /*
             * But the IP address is different from the last one we knew
             * Update it
             */
            debug(LOG_DEBUG, "Level %d: Updating last_ip IP of server [%s] to [%s]", level, hostname, ip);
            if (auth_server->last_ip)
                strncpy(auth_server->last_ip, ip, sizeof(ip)-1);
            else
                auth_server->last_ip = strdup(ip);

            /* Update firewall rules */
            fw_clear_authservers();
            fw_set_authservers();
        }
        else 
        {
            /*
             * IP is the same as last time
             */
        }

        /*
         * Connect to it
         */
        int port = 0;
#ifdef USE_CYASSL
        if (auth_server->authserv_use_ssl) 
        {
            debug(LOG_DEBUG, "Level %d: Connecting to SSL auth server %s:%d", level, hostname, auth_server->authserv_ssl_port);
            port = htons(auth_server->authserv_ssl_port);
        }
        else
#endif
        {
            debug(LOG_DEBUG, "Level %d: Connecting to auth server %s:%d", level, hostname, auth_server->authserv_http_port);
            port = htons(auth_server->authserv_http_port);
        }

        their_addr.sin_port = port;
        their_addr.sin_family = AF_INET;
        their_addr.sin_addr = *h_addr;
        memset(&(their_addr.sin_zero), 0, sizeof(their_addr.sin_zero));
        free(h_addr);

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            debug(LOG_ERR, "Level %d: Failed to create a new SOCK_STREAM socket: %s", level, strerror(errno));
            return (-3);
        }

        if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
            /*
             * Failed to connect
             * Mark the server as bad and try the next one
             */
            debug(LOG_DEBUG, "Level %d: Failed to connect to auth server %s:%d (%s). Marking it as bad and trying next if possible",
                  level, hostname, ntohs(port), strerror(errno));
            close(sockfd);
            mark_auth_offline2(auth_server, false);
            mark_auth_server_bad(auth_server);
            return _connect_auth_server(level); /* Yay recursion! */
        } else {
            /*
             * We have successfully connected
             */
            mark_auth_online2(auth_server, sockfd);
            debug(LOG_DEBUG, "Level %d: Successfully connected to auth server %s:%s:%d", level, hostname, ip, ntohs(port));
            return sockfd;
        }
    }
}


int connect_auth_agent()
{
    int sockfd;

    LOCK_CONFIG();
    sockfd = _connect_auth_agent(0);
    UNLOCK_CONFIG();

    if (sockfd < 0) {
        #if 0 /* Note: here differient with connect_auth_server, fw_set_auth** actions are excuted outside, see connect_agent */
        int got_authdown_ruleset = (NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1);
        if(got_authdown_ruleset)
            fw_set_authdown();
        #endif
        debug(LOG_ALERT, "Failed to connect to any of the auth agents, ret: %d", sockfd);  
    } 
    else
    {
        debug(LOG_INFO, "Connected to auth agent");
    }
    return (sockfd);
}

int _connect_auth_agent(int level)
{
    T_CONFIG *config = config_get_config();
    return _connect_auth(&config->auth_agents, level);
}

int _connect_auth(t_auth_serv_mgmt_t* serverMgmt, int level)
{
    T_CONFIG* config = config_get_config();
    t_auth_serv *auth_server = NULL;
    t_popular_server *popular_server = NULL;
    struct in_addr *h_addr = NULL;
    int num_servers = 0;
    char *hostname = NULL;
    char ip[MAX_IP_ADDR_LEN]={0};
    struct sockaddr_in their_addr;
    int sockfd;
    int conret=-1;
    
    /* If there are no auth servers, error out, from scan-build warning. */
    if (NULL == serverMgmt) {
        debug(LOG_WARNING, "_connect_auth: null target list");
        return (-1);
    }

    /* XXX level starts out at 0 and gets incremented by every iterations. */
    level++;

    /*
     * Let's calculate the number of servers we have
     */
    for (auth_server = serverMgmt->auth_server; auth_server; auth_server = auth_server->next) {
        num_servers++;
    }
    debug(LOG_DEBUG, "Level %d: Calculated %d target(s) in list {%s}", level, num_servers, serverMgmt->name);

    if (level > num_servers) {
        /*
         * We've called ourselves too many times
         * This means we've cycled through all the servers in the server list
         * at least once and none are accessible
         */
        return (-5);
    }

    /*
     * Let's resolve the hostname of the top server to an IP address
     */
    auth_server = serverMgmt->auth_server;
    if(!auth_server->auth_server_mgmt)
    {
        return (-2);
    }
    
    hostname = auth_server->authserv_hostname;
    if(auth_server->authserv_hostip)
    {
        debug(LOG_DEBUG, "Level %d: Direct %s target {%s}", level, serverMgmt->name, auth_server->authserv_hostip);
        h_addr = wd_gethostbyipstring(auth_server->authserv_hostip);
        hostname = auth_server->authserv_hostip;
    }
    else if(NULL != hostname)
    {
        debug(LOG_DEBUG, "Level %d: Resolving %s target {%s}", level, serverMgmt->name, hostname);
        h_addr = wd_gethostbyname(hostname);
    }

    if (!h_addr) {
        /*
         * DNS resolving it failed
         */
        debug(LOG_DEBUG, "Level %d: Resolving %s target {%s} failed", level, serverMgmt->name, hostname);

        for (popular_server = config->popular_servers; popular_server; popular_server = popular_server->next) {
            debug(LOG_DEBUG, "Level %d: Resolving popular server [%s]", level, popular_server->hostname);
            h_addr = wd_gethostbyname(popular_server->hostname);
            if (h_addr) {
                debug(LOG_DEBUG, "Level %d: Resolving popular server [%s] succeeded = [%s]", level, popular_server->hostname,
                      inet_ntoa(*h_addr));
                break;
            } else {
                debug(LOG_DEBUG, "Level %d: Resolving popular server [%s] failed", level, popular_server->hostname);
            }
        }

        /* 
         * If we got any h_addr buffer for one of the popular servers, in other
         * words, if one of the popular servers resolved, we'll assume the DNS
         * works, otherwise we'll deal with net connection or DNS failure.
         */
        if (h_addr) 
        {
            free(h_addr);
            /*
             * Yes
             *
             * The auth server's DNS server is probably dead. Try the next auth server
             */
            debug(LOG_DEBUG, "Level %d: Marking %s in list {%s} as bad and trying next if possible", level, hostname, serverMgmt->name);
            if (auth_server->last_ip) {
                free(auth_server->last_ip);
                auth_server->last_ip = NULL;
            }

            mark_auth_offline2(auth_server, false);
            mark_auth_server_bad2(auth_server);
            return _connect_auth(serverMgmt, level);
        }
        else 
        {
            /*
             * No
             *
             * It's probably safe to assume that the internet connection is malfunctioning
             * and nothing we can do will make it work
             */
            debug(LOG_DEBUG, "Level %d: Failed to resolve target {%s} and all popular servers. "
                  "The internet connection is probably down", level, serverMgmt->name);
            mark_offline();
            return (-6);
        }
    }
    else
    {
        /*
         * DNS resolving was successful
         */
        mark_online();
        strncpy(ip, inet_ntoa(*h_addr), sizeof(ip)-1);
        debug(LOG_DEBUG, "Level %d: Resolving target {%s} [%s] succeeded = [%s]", level, serverMgmt->name, hostname, ip);

        if (!auth_server->last_ip || strcmp(auth_server->last_ip, ip) != 0) 
        {
            /*
             * But the IP address is different from the last one we knew
             * Update it
             */
            debug(LOG_DEBUG, "Level %d: Updating last_ip IP of target {%s} [%s] to [%s]", level, serverMgmt->name, hostname, ip);
            if (auth_server->last_ip)
                strncpy(auth_server->last_ip, ip, sizeof(ip)-1);
            else
                auth_server->last_ip = strdup(ip);
            /* Update firewall rules */
            if(auth_server->authserv_http_port)
            {
                fw_clear_authservers();
                fw_set_authservers();
            }
        } 
        else
        {
            /*
             * IP is the same as last time
             */
        }

        /*
         * Connect to it
         */
        int port = 0;
#ifdef USE_CYASSL
        if (auth_server->authserv_use_ssl) 
        {
            debug(LOG_DEBUG, "Level %d: Connecting to SSL target {%s} %s:%d", 
                             level, serverMgmt->name, hostname, auth_server->authserv_ssl_port);
            port = htons(auth_server->authserv_ssl_port);
        }
        else
#endif
        {
            if(auth_server->authserv_http_port)
            {
                port = auth_server->authserv_http_port;
            }
            else
            {
                port = auth_server->authagent_tcp_port;
            }
            debug(LOG_DEBUG, "Level %d: Connecting to target {%s} %s:%d", level, serverMgmt->name, hostname, port);
            port = htons(port);
        }

        their_addr.sin_port = port;
        their_addr.sin_family = AF_INET;
        their_addr.sin_addr = *h_addr;
        memset(&(their_addr.sin_zero), 0, sizeof(their_addr.sin_zero));
        free(h_addr);

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
            debug(LOG_ERR, "Level %d: Failed to create a new SOCK_STREAM socket: %s", level, strerror(errno));
            //mark_auth_offline2(auth_server, false);
            return (-3);
        }
        
#if USE_ALARM
        struct sigaction sa;
        sa.sa_handler = alarm_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_INTERRUPT|SA_RESETHAND;
        sigaction(SIGALRM, &sa, NULL);
        alarm(3);
        conret = connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr));
        alarm(0);
#else
        conret = connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr));
#endif

        if (conret == -1) {
            /*
             * Failed to connect
             * Mark the server as bad and try the next one
             */
            debug(LOG_DEBUG, "Level %d: Failed to connect to target {%s} %s(%s):%d %s. Marking it as bad and trying next if possible",
                  level, serverMgmt->name, hostname, ip, ntohs(port), strerror(errno));
            close(sockfd);
            mark_auth_offline2(auth_server, false);
            mark_auth_server_bad2(auth_server);
            return _connect_auth(serverMgmt, level); /* Yay recursion! */
        }
        else
        {
            /*
             * We have successfully connected
             */
            mark_auth_online2(auth_server, sockfd);
            debug(LOG_DEBUG, "Level %d: Successfully connected to target {%s} %s(%s):%d", level, serverMgmt->name, hostname, ip, ntohs(port));
            return sockfd;
        }
    }
}


