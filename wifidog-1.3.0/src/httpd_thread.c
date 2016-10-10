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

/** @file httpd_thread.c
    @brief Handles on web request.
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "httpd.h"

#include "../config.h"
#include "common.h"
#include "debug.h"
#include "httpd_thread.h"

static void http_errcode_process(request* r, int err)
{
    switch(err)
    {
        case HTTP_ERR_CONN_TIMEOUT:
        {
            debug(LOG_INFO, "Connection from %s timeout", r->clientAddr);
        }
        break;
        case HTTP_ERR_UNKOWN_METHOD:
        {
            char methodStr[HTTP_METHOD_MAX_LEN]={0};
            debug(LOG_INFO, "%s request[%s] received from %s", 
            httpdMethod2Name(httpdRequestMethod(r), methodStr, HTTP_METHOD_MAX_LEN), r->readBuf, r->clientAddr);
        }
        break;
        case HTTP_ERR_SOCKET_OR_READ:
        {
            debug(LOG_INFO, "Read from connection %s socket error", r->clientAddr);
        }
        break;
        default:
            debug(LOG_ERR, "Wrong error code:%d with request from %s", err, r->clientAddr);
        break;
    }
    return;
}

/** Main request handling thread.
@param args Two item array of void-cast pointers to the httpd and request struct
*/
void thread_httpd(void* args)
{
    void**   params;
    httpd*   webserver;
    request* r;
    int ret;
    
    params = (void **)args;
    webserver = *params;
    r = *(params + 1);
    free(params); /* XXX We must release this ourselves. */
    
    ret = httpdReadRequest(webserver, r);
    if(HTTP_RET_SUCCESS==ret)
    {
        /*
        * We read the request fine
        */
        char methodStr[HTTP_METHOD_MAX_LEN]={0};
        debug(LOG_INFO, "Http request from %s \"%s %s %s %s %s %s\"", 
             r->clientAddr, httpdMethod2Name(httpdRequestMethod(r), methodStr, HTTP_METHOD_MAX_LEN), 
             httpdRequestHost(r), httpdRequestPath(r), r->request.query[0] ? "?" : "", r->request.query, 
             httpdRequestVersion(r));
        httpdProcessRequest(webserver, r);
        debug(LOG_DEBUG, "Returned from http request for %s", r->clientAddr);
    }
    else 
    {
        http_errcode_process(r, ret);
    }
    debug(LOG_DEBUG, "Closing connection with %s", r->clientAddr);
    httpdEndRequest(r);
}

