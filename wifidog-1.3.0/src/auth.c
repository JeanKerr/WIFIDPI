/* vim: set et sw=4 ts=4 sts=4 : */
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
/** @file auth.c
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#include "common.h"

#include <sys/types.h>
#include <sys/socket.h>
#include "httpd.h"
#include "http.h"
#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "util.h"
#include "wd_util.h"

/** Launches a thread that periodically checks if any of the connections has timed out
@param arg Must contain a pointer to a string containing the IP adress of the client to check to check
@todo Also pass MAC adress? 
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
#define UPDATE_COUNTERS_PERIOD_IN_SECS 30
void thread_client_timeout_check(const void* arg)
{
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;
    int CntPerRnd = config_get_config()->checkinterval/UPDATE_COUNTERS_PERIOD_IN_SECS;

    while (1)
    {
        /* Sleep for config.checkinterval seconds... */
        timeout.tv_sec = time(NULL) + UPDATE_COUNTERS_PERIOD_IN_SECS;
        timeout.tv_nsec = 0;
        
        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);
        
        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
        
        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);
        
        debug(LOG_TRACE, "Running iptables_fw_counters_update()");
        if (0 != iptables_fw_counters_update()) 
        {
            debug(LOG_ERR, "Could not get counters from firewall!");
            inner_stt.iptblsUpdErr++;
            continue;
        }
        inner_stt.iptblsUdpCnt++;
        if(0!=inner_stt.iptblsUdpCnt%CntPerRnd) continue;
        
        debug(LOG_TRACE, "Running client_timeout_check()");
        inner_stt.logoutBytimedOut+= timeout_client();
    }
}

/**
 * @brief Logout a client and report to auth server.
 *
 * This function assumes it is being called with the client lock held! This
 * function remove the client from the client list and free its memory, so
 * client is no langer valid when this method returns.
 *
 * @param client Points to the client to be logged out
 */
bool logout_client(t_client* client, bool active)
{
    t_authresponse authresponse;
    bool ret=false;
    t_client* pClient = client_dup(client);

    if(pClient)
    {
        if(0 == strlen(pClient->phone) || 0 == strlen(pClient->token) || 0 == strlen(pClient->record_id))
        {
            inner_stt.logoutUnAuthened++;
            ret=true;
        }
        else
        {
            debug(LOG_NOTICE, "Client[IP:%s, MAC:%s, Phone:%s] logout", pClient->ip, pClient->mac, pClient->phone);
            if(fw_deny(client))
            {
                inner_stt.logoutCnt++;
                ret=true;
            }
            else
            {
                inner_stt.logoutExcuteFail++;
            }
        }
    } 

    client_list_remove(client);
    client_free_node(client);

    /* Advertise the logout if we have an auth server */
    if (NULL != get_auth_server() && active && pClient) 
    {
        UNLOCK_CLIENT_LIST();
        auth_server_request(&authresponse, E_REQUEST_TYPE_LOGOUT, pClient);

        if (authresponse.authcode == AUTH_ALLOWED)
        {
            inner_stt.notifyAuthServerSuccess++;
        }
        else
        {
            debug(LOG_WARNING, "Auth server error when [IP:%s, MAC:%s, Phone:%s] logout", 
                           pClient->ip, pClient->mac, pClient->phone);
            inner_stt.notifyAuthServerFail++;
        }
        LOCK_CLIENT_LIST();
    }

    if(pClient)
    {
        client_list_destroy(pClient);    /* Free the cloned client */
    }
    return ret;
}

/** Authenticates a single client against the central server and returns when done
 * Alters the firewall rules depending on what the auth server says
@param r httpd request struct
*/
void authenticate_client(httpd* server, request* r)
{
    t_client *client, *pClient;
    t_authresponse auth_response;
    char *pToken;
    httpVar *var;

    LOCK_CLIENT_LIST();

    pClient = client_dup(client_list_find_by_ip(r->clientAddr));

    UNLOCK_CLIENT_LIST();

    if (pClient == NULL) 
    {
        debug(LOG_ERR, "authenticate_client(): Could not find client for %s", r->clientAddr);
        return;
    }
    
    /* Users could try to log in(so there is a valid token in
     * request) even after they have logged in, try to deal with
     * this */
    if ((var = httpdGetVariableByName(r, "token")) != NULL) 
    {
        pToken = var->value;
    }
    else
    {
        pToken = pClient->token;
    }
    
    /* 
     * At this point we've released the lock while we do an HTTP request since it could
     * take multiple seconds to do and the gateway would effectively be frozen if we
     * kept the lock.
     */
    auth_server_request(&auth_response, E_REQUEST_TYPE_LOGIN, pClient);
    
    LOCK_CLIENT_LIST();
    /* can't trust the client to still exist after n seconds have passed */
    client = client_list_find_by_client(pClient);
    if (client) 
    {
        client_update(client, NULL, get_terminal_type(r->request.user_agent), NULL, pToken, get_millisecond());
        process_auth_result(server, r, client, auth_response.authcode);
    }
    UNLOCK_CLIENT_LIST();
    
    client_list_destroy(pClient);    /* Free the cloned client */
    return;
}

bool process_auth_result(httpd* server, request* r, t_client* client, t_authcode eCode)
{
    char* urlFragment = NULL;
    bool ret=false;
    T_CONFIG *config = config_get_config();

    if (NULL == client) 
    {
        debug(LOG_ERR, "process_auth_result find error para: null client");
        return ret;
    }
    
    /* Prepare some variables we'll need below */
    switch (eCode) 
    {
        case AUTH_ERROR: /* Error talking to central server */
        {
            debug(LOG_ERR, "Auth ERROR with token %s for IP:%s MAC:%s", client->token, client->ip, client->mac);
            client_list_delete(client);
            if(config->local_auth_flag && server && r)
            {
                http_send_page(server, r, "Auth Error!", "Error: authentication infomation is invalid");
            }
        }
        break;
        
        case AUTH_DENIED: /* Central server said invalid token */
        {
            debug(LOG_NOTICE, "Auth DENIED with token %s for IP:%s MAC:%s -del firewall rule and redirect to denied message",
                  client->token, client->ip, client->mac);
            ret = fw_deny(client);
            if(config->local_auth_flag && server && r)
            {
                http_send_redirect_to_local_auth(server, r, NULL, "Redirect to login page");
            }
        }
        break;
        
        case AUTH_VALIDATION: /* They just got validated for X minutes to check their email */
        {
            debug(LOG_NOTICE, "Auth VALIDATION with token %s for IP:%s MAC:%s -add firewall rule and redirect to activate message", 
                    client->token, client->ip, client->mac);
            /* we could open just the address scope where email address@, eg:www.163.net??? */
            fw_allow(client, FW_MARK_PROBATION);
            if(config->local_auth_flag && server && r)
            {
                http_send_redirect_to_local_auth(server, r, NULL, "Redirect to login page");
            }
        }
        break;

        case AUTH_VALIDATION_FAILED:
        {
            /* Client had X minutes to validate account by email and didn't = too late */
            debug(LOG_NOTICE, "Auth VALIDATION_FAILED with token %s for IP:%s MAC:%s -redirect to failed_validation message", 
                    client->token, client->ip, client->mac);
            if(logout_client(client, false))
                inner_stt.logoutValidateFail++;
            if(config->local_auth_flag && server && r)
            {
                http_send_redirect_to_local_auth(server, r, "http://ideal.sh.cn/", "Redirect to login page");
            }
        }
        break;

        case AUTH_ALLOWED: /* Logged in successfully as a regular account */
        {
            debug(LOG_NOTICE, "Auth ALLOWED with token %s for Client[IP:%s, MAC:%s, Phone:%s]", 
                              client->token, client->ip, client->mac, client->phone);
            ret = fw_allow(client, FW_MARK_KNOWN);
            debug(LOG_INFO, "served clients: %llu", inner_stt.loginCnt);
            if(config->local_auth_flag && server && r)
            {
                http_send_redirect(server, r, "http://ideal.sh.cn/", "Redirect to main page");
            }
        }
        break;

        default:
        {
            debug(LOG_WARNING, "Unkown validation code %d, with token %s for IP:%s MAC:%s -send error message",
                    eCode, client->token, client->ip, client->mac);
            if(config->local_auth_flag && server && r)
            {
                http_send_page(server, r, "Internal Error", "We can not validate your request at this time");
            }
        }
        break;
    }
    
    if(urlFragment)
    {
        free(urlFragment);
    }
    
    return ret;
}



