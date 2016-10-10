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

#define _GNU_SOURCE
#include "common.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "../config.h"
#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "ping_thread.h"
#include "httpd_thread.h"
#include "util.h"
#include "centralserver.h"
#include "firewall.h"
#include "gateway.h"
#include "simple_http.h"
#include "cJSON.h"
#include "portal_thread.h"

static int check_n_update_portal(void);

/** Launches a thread that periodically checks in with the auth server to perform heartbeat function.
@param arg NULL
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void thread_portal_update(void *arg)
{
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;
    int cnt = 0;
    while (1) {
        /* Make sure we check the servers at the very begining */
        debug(LOG_DEBUG, "Running thread_portal_update()");
        cnt = check_n_update_portal();

        /* Sleep for config.checkinterval seconds... */
        timeout.tv_sec = time(NULL) + cnt; //config_get_config()->checkinterval * cnt;
        timeout.tv_nsec = 0;

        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);

        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);
    }
}

/** @internal
 * This function does the actual request.
 */
static int check_n_update_portal(void)
{
    char request[MAX_BUF]={0};
    int sockfd;
    int ret;
    cJSON* pJson=NULL;
    char *ParseJsonOut=NULL;
    char newVersion[PORTAL_VERSTRING_LEN]={0};
    char* pFound=NULL;
    sighandler_t old_handler;
    bool updSuc = false;
    const T_CONFIG *config = config_get_config();
    t_auth_serv *auth_server = get_auth_server();
    static int waitSec = 1;
    static bool authdown = FALSE;

    debug(LOG_DEBUG, "Entering check_n_update_portal()");
    /*
     * The check_n_update_portal thread does not really try to see if the auth server is actually
     * working. Merely that there is a web server listening at the port. And that
     * is done by connect_auth_server() internally.
     */
    sockfd = connect_auth_server();
    if (sockfd < 0) {
        if(!authdown)
        {
            authdown = TRUE;
            debug(LOG_WARNING, "check_n_update_portal connect_auth_server failed");
        }
        else
        {
            debug(LOG_DEBUG, "check_n_update_portal connect_auth_server failed");
        }
        return 10;
    }
    authdown = FALSE;
    
    if(!config->local_auth_flag)
    {
        return 300;
    }

    /*
     * send update request
     */
    snprintf(request, sizeof(request) - 1,
             "GET %s%s%splace_code=%s&version=%s HTTP/%s\r\n"
             "User-Agent: %s %s\r\n"
             "Host: %s\r\n"
             "\r\n",
             auth_server->active_path,
             auth_server->authserv_update_portal_path_fragment, auth_server->authserv_seperator,
             config->place_code,
             get_portal_version_string(),
             config->http_version,
             config->company, config->version, 
             (auth_server->authserv_hostip!=NULL) ? auth_server->authserv_hostip:auth_server->last_ip);

    char *res;
    char *JsonHead;
#ifdef USE_CYASSL
    if (auth_server->authserv_use_ssl) 
    {
        res = https_get(sockfd, request, auth_server->authserv_hostname);
    } 
    else
#endif
    {
        res = http_get2(sockfd, request, ']');
    }
    if (NULL == res || NULL == (JsonHead=strchr(res, '['))) 
    {
        debug(LOG_ERR, "There was a problem with update response from the portal server!");
        goto FAIL;
    } 
    
    /* Utilize cJSON lib to parse version string, coco. *
     * Response contains placecode and version.          *
     * res string format example:                                   *
     * "[\n {\n \"placecode\": \"200\",\n \"version\": \"1.0\",\n \"remark01\": \" \",\n \"remark02\": \" \",\n \"remark03\": \" \",\n \"remark04\": \" \",\n \"remark05\": \" \"\n }\n ]"; */
    
    debug(LOG_DEBUG, "check_n_update_portal get correct response:\n%s\n", JsonHead);
    pJson = cJSON_Parse(JsonHead);
    if (!pJson) 
    {
        debug(LOG_ERR, "check_n_update_portal JSON Parse Error before:\n%s\n",cJSON_GetErrorPtr());
    }
    else
    {
        ParseJsonOut = cJSON_Print(pJson);
        debug(LOG_DEBUG, "ParseJsonOut: %s", ParseJsonOut);
        pFound = cJSON_FindStrNStrValue(pJson, "version", newVersion, PORTAL_VERSTRING_LEN-1);
        cJSON_Delete(pJson);
        if(ParseJsonOut) 
            free(ParseJsonOut);
        free(res);

        if(pFound)
        {
            debug(LOG_DEBUG, "portal server gives correct response with version:%s", newVersion);
            set_portal_version_string(newVersion);

            /* http://localhost:8080/WIFI_YUN/system/wifi/download/place_code/version */
            memset(request, 0, sizeof(request));

            snprintf(request, sizeof(request)-1, "wget -c -d -o %s/dload.log -O %s/%s --ftp-user=test --ftp-password=123456789 %s://%s:%d%s%s/%s/%s",
                config->portal_save_path,
                config->portal_save_path,
                DEFAULT_PORTAL_FILENAME,
                auth_server->authserv_use_ssl? "https":"http",
                auth_server->authserv_hostname,
                auth_server->authserv_http_port,
                auth_server->active_path,
                auth_server->authserv_dload_portal_path_fragment,
                config->place_code,
                get_portal_version_string());

            old_handler = signal(SIGCHLD, SIG_DFL);
            ret = system(request);
            if(ret==-1 || WIFSIGNALED(ret) || WIFSTOPPED(ret))
            {
                debug(LOG_ERR, "update portal[%s] failed:%s signal:[%d,%d]", request, strerror(errno), WTERMSIG(ret),  WTERMSIG(ret));
            }
            else
            {
                debug(LOG_NOTICE, "update portal[%s] successfully finished:%d", request, ret);
                updSuc = true;
            }
            signal(SIGCHLD, old_handler);
            if(updSuc) waitSec = 1;
                return 60*24*60; //update once per 24hs 
        }
    }

FAIL:
    if(!updSuc && waitSec < 60*12*60)
        waitSec=waitSec*2;

    return waitSec;
}


void thread_listen_web_connect(void *arg)
{
    int result;
    request *r;
    httpd* WebServer = arg;
    void **params;
    struct timeval time_out;
    pthread_t tid = pthread_self();
    unsigned int random = (unsigned int)tid;
    
    time_out.tv_sec = 60 + random%60;
    time_out.tv_usec= 0;
    
    debug(LOG_DEBUG, "WebServer thread[%lu] waiting for connections on ip:port[%s:%d] in every %lu seconds per round...", 
              tid, WebServer->host, WebServer->port, time_out.tv_sec);
    while (1) {
        r = httpdGetConnection(WebServer, &time_out);

        /* We can't convert this to a switch because there might be
         * values that are not -1, 0 or 1. */
        if (WebServer->lastError == -1) {
            /* Interrupted system call */
            if (NULL != r) {
                httpdEndRequest(r);
            }
        } else if (WebServer->lastError < -1) {
            /*
             * FIXME
             * An error occurred - should we abort?
             * reboot the device ?
             */
            debug(LOG_ERR, "FATAL: httpdGetConnection returned unexpected value %d, exiting.", WebServer->lastError);
            termination_handler(0);
        } else if (r != NULL) {
            /*
             * We got a connection
             *
             * We should create another thread
             */
            debug(LOG_DEBUG, "Received connection from %s, spawning worker thread", r->clientAddr);
            /* The void**'s are a simulation of the normal C
             * function calling sequence. */
            params = safe_malloc(2 * sizeof(void *));
            *params = WebServer;
            *(params + 1) = r;

            result = pthread_create(&tid, NULL, (void *)thread_httpd, (void *)params);
            if (result != 0) {
                debug(LOG_ERR, "FATAL: Failed to create a new thread (httpd) - exiting");
                termination_handler(0);
            }
            pthread_detach(tid);
        } else {
            /* webserver->lastError should be 2 */
            /* XXX We failed an ACL.... No handling because
             * we don't set any... */
        }
    }

}

/*************add for version update*******************/
pthread_mutex_t version_update_mutex = PTHREAD_MUTEX_INITIALIZER;
int version_update = VERSION_UPDATE_DONE;

VERSION_UPDATE_INFO ver_update_info;

int version_update_do(void)
{
    int updSuc = 0;
    int ret    = 0;
    sighandler_t old_handler;
    char request[200]={0};

    debug(LOG_INFO, "[%s] enter ", __FUNCTION__);

    memset(request, 0, sizeof(request));
    snprintf(request, sizeof(request)-1, "wget -d -o %s/version-update.log -O %s/%s --ftp-user=%s --ftp-password=%s %s",
        VERSION_PATH,
        VERSION_PATH,
        VERSION_NAME,
        ver_update_info.user,
        ver_update_info.pwd,
        ver_update_info.url);

    old_handler = signal(SIGCHLD, SIG_DFL);
    ret = system(request);
    if((-1 == ret) || (0 == WIFEXITED(ret)) || WEXITSTATUS(ret))
    {
        debug(LOG_ERR, "[%s]download version[%s] failed:%s signal:[%d,%d]", __FUNCTION__, request, strerror(errno),WIFEXITED(ret),  WEXITSTATUS(ret));
        updSuc = -1;
    }
    else
    {
        debug(LOG_INFO, "[%s]download verion[%s] successfully finished:%d", __FUNCTION__, request, ret);
    }
    signal(SIGCHLD, old_handler);

    if (0 != updSuc)
    {
        return updSuc;
    }

    memset(request, 0, sizeof(request));
    //snprintf(request, sizeof(request)-1, "mtd -r write %s/%s firmware", VERSION_PATH, VERSION_NAME);
    snprintf(request, sizeof(request)-1, "sysupgrade %s/%s", VERSION_PATH, VERSION_NAME);

    old_handler = signal(SIGCHLD, SIG_DFL);
    ret = system(request);
    if((-1 == ret) || (0 == WIFEXITED(ret)) || WEXITSTATUS(ret))
    {
        debug(LOG_ERR, "[%s]update version[%s] failed:%s signal:[%d,%d]", __FUNCTION__, request, strerror(errno), WIFEXITED(ret),  WEXITSTATUS(ret));
        updSuc = -1;
    }
    else
    {
        debug(LOG_INFO, "[%s]update verion[%s] successfully finished:%d", __FUNCTION__, request, ret);
    }
    signal(SIGCHLD, old_handler);

    return updSuc;
}

void version_update_delay(int minutes)
{
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;

    /* Sleep for 5 minutes... */
    timeout.tv_sec = time(NULL) + minutes*60;
    timeout.tv_nsec = 0;

    /* Mutex must be locked for pthread_cond_timedwait... */
    pthread_mutex_lock(&cond_mutex);

    /* Thread safe "sleep" */
    pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

    /* No longer needs to be locked */
    pthread_mutex_unlock(&cond_mutex);

    return;
}

void version_update_done(void)
{
    LOCK_VERSION_UPDATE();
    version_update = VERSION_UPDATE_DONE;
    UNLOCK_VERSION_UPDATE();

    return;
}

void version_update_resp(tcp_request* r, int status)
{
    char* ParseJsonOut = NULL;
    cJSON* root        = NULL;

    root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "taskId", cJSON_CreateString(ver_update_info.taskID));
    cJSON_AddItemToObject(root, "status", cJSON_CreateNumber(status));

    ParseJsonOut = cJSON_Print(root);
    if (NULL != ParseJsonOut)
    {
        debug(LOG_INFO, "[%s]ParseJsonOut: %s", __FUNCTION__, ParseJsonOut);

        tcpSetResponseHead(r, &r->head);
        tcpSetResponseData(r, ParseJsonOut, strlen(ParseJsonOut));
        tcpOutputResponse(r);
    
        free(ParseJsonOut);
    }

    cJSON_Delete(root);
    return;    
}

bool version_update_start(char* msgData, unsigned int msgLen, tcp_request* r)
{
    char* JsonHead     = NULL;
    char* ParseJsonOut = NULL;
    cJSON* pJson       = NULL;


    if ((NULL == msgData) || (NULL == (JsonHead = strchr(msgData, '{'))))
    {
        debug(LOG_ERR, "[%s]msgData or JsonHead is null!!!", __FUNCTION__);
        return FALSE;
    }

    /* {"ftpPwd":"test","taskId":"559eac45f03343b88bb97cdbad1f681a","time":"","ftpUser":"test","url":"ftp://test.com"} */
    debug(LOG_INFO, "[%s]get verion update info:%s ", __FUNCTION__, msgData);
    pJson = cJSON_Parse(JsonHead);
    if (!pJson) 
    {
        debug(LOG_ERR, "[%s] JSON Parse Error before:\n%s\n", __FUNCTION__, cJSON_GetErrorPtr());
        return FALSE;
    }
    else
    {
        ParseJsonOut = cJSON_Print(pJson);
        if (NULL != ParseJsonOut)
        {
            debug(LOG_INFO, "[%s]ParseJsonOut: %s", __FUNCTION__, ParseJsonOut);
            free(ParseJsonOut);
        }

        memset(&ver_update_info, 0, sizeof(VERSION_UPDATE_INFO));
        cJSON_FindStrNStrValue(pJson, "taskId", ver_update_info.taskID, sizeof(ver_update_info.taskID)-1);
        cJSON_FindStrNStrValue(pJson, "url", ver_update_info.url, sizeof(ver_update_info.url)-1);
        cJSON_FindStrNStrValue(pJson, "ftpUser", ver_update_info.user, sizeof(ver_update_info.user)-1);
        cJSON_FindStrNStrValue(pJson, "ftpPwd", ver_update_info.pwd, sizeof(ver_update_info.pwd)-1);
        cJSON_Delete(pJson);
    }

    if ((0 == strlen(ver_update_info.taskID)) || (0 == strlen(ver_update_info.url)) || 
        (0 == strlen(ver_update_info.user)) || (0 == strlen(ver_update_info.pwd)))
    {
        debug(LOG_ERR, "[%s] taskID:%lu, url:%lu, user:%lu, pwd:%lu", __FUNCTION__, 
            strlen(ver_update_info.taskID),
            strlen(ver_update_info.url),
            strlen(ver_update_info.user),
            strlen(ver_update_info.pwd));
        version_update_resp(r, 0);
        version_update_done();
        return FALSE;
    }

    LOCK_VERSION_UPDATE();
    version_update = VERSION_UPDATE_START;
    UNLOCK_VERSION_UPDATE();

    version_update_resp(r, 1);
    debug(LOG_INFO, "[%s]version update start version_update:%d taskID:%s, url:%s, user:%s, pwd:%s", __FUNCTION__,version_update,
        ver_update_info.taskID,
        ver_update_info.url,
        ver_update_info.user,
        ver_update_info.pwd);
    return TRUE;
}


void thread_version_update(void *arg)
{
    static int count = 0;

    while (1) 
    {
        debug(LOG_INFO, "[%s]version update scanning version_update:%d ", __FUNCTION__, version_update);

        if (version_update != VERSION_UPDATE_START)
        {
            version_update_delay(2);
            continue;
        }

        debug(LOG_INFO, "[%s]version update start version_update:%d ", __FUNCTION__, version_update);

        if (0 != version_update_do())
        {
            count++;
            debug(LOG_ERR, "[%s]version_update_do failed, count:%d !!!! ", __FUNCTION__, count);

            if (count >= 3)
            {
                count = 0;
                version_update_done();
            }
                        
            version_update_delay(1);
            continue;
        }

        count = 0;
        version_update_done();
        debug(LOG_INFO, "[%s]version update done version_update:%d ", __FUNCTION__, version_update);
    }
}


    /*************add for router reset*******************/
bool router_reset(char* msgData, unsigned int msgLen, tcp_request* r)
{
    int ret    = 0;
    sighandler_t old_handler;
    char request[200]={0};

    if (NULL == r)
    {
        debug(LOG_ERR, "[%s]para is null!!!", __FUNCTION__);
        return FALSE;
    }

    if  (E_TYPE_RESET_OS != r->head.type)
    {
        debug(LOG_ERR, "[%s]type is error(%d)!!!", __FUNCTION__, r->head.type);
        return FALSE;
    }

    debug(LOG_INFO, "[%s]rcv romote order for router reset ", __FUNCTION__);
    snprintf(request, sizeof(request)-1, "reboot");

    old_handler = signal(SIGCHLD, SIG_DFL);
    ret = system(request);
    if((-1 == ret) || (0 == WIFEXITED(ret)) || WEXITSTATUS(ret))
    {
        debug(LOG_ERR, "[%s]route reset[%s] failed:%s signal:[%d,%d]", __FUNCTION__, request, strerror(errno),WIFEXITED(ret),  WEXITSTATUS(ret));
    }
    else
    {
        debug(LOG_INFO, "[%s]route reset[%s] successfully finished:%d", __FUNCTION__, request, ret);
    }
    signal(SIGCHLD, old_handler);

    return TRUE;
}




