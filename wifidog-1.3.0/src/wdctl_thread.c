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
/** @file wdctl_thread.c
    @brief Monitoring and control of process, server part
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#define _GNU_SOURCE
#include "common.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "httpd.h"
#include "util.h"
#include "wd_util.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "wdctl_thread.h"
#include "commandline.h"
#include "gateway.h"
#include "safe.h"


static int create_unix_socket(const char *);
static int write_to_socket(int, char *, size_t);
static void *thread_wdctl_handler(void *);
static void wdctl_pass(int, const char *);
static void wdctl_reset(int, const char *);
static void wdctl_status(int);
static void wdctl_statistics(int);
static void wdctl_stop(int);
static void wdctl_restart(int);
static void wdctl_debug(int, const char *);

static int wdctl_socket_server;

static int create_unix_socket(const char *sock_name)
{
    struct sockaddr_un sa_un;
    int sock;

    memset(&sa_un, 0, sizeof(sa_un));

    if (strlen(sock_name) > (sizeof(sa_un.sun_path) - 1)) {
        /* TODO: Die handler with logging.... */
        debug(LOG_ERR, "WDCTL socket name too long");
        return -1;
    }

    sock = socket(PF_UNIX, SOCK_STREAM, 0);

    if (sock < 0) {
        debug(LOG_DEBUG, "Could not get unix socket: %s", strerror(errno));
        return -1;
    }
    debug(LOG_DEBUG, "Got unix socket %d", sock);

    /* If it exists, delete... Not the cleanest way to deal. */
    unlink(sock_name);

    //debug(LOG_DEBUG, "Filling sockaddr_un");
    strcpy(sa_un.sun_path, sock_name);
    sa_un.sun_family = AF_UNIX;

    debug(LOG_DEBUG, "Binding socket (%s) (%lu)", sa_un.sun_path, strlen(sock_name));

    /* Which to use, AF_UNIX, PF_UNIX, AF_LOCAL, PF_LOCAL? */
    if (bind(sock, (struct sockaddr *)&sa_un, sizeof(struct sockaddr_un))) {
        debug(LOG_ERR, "Could not bind unix socket: %s", strerror(errno));
        close(sock);
        return -1;
    }

    if (listen(sock, 5)) {
        debug(LOG_ERR, "Could not listen on control socket: %s", strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

/** Launches a thread that monitors the control socket for request
@param arg Must contain a pointer to a string containing the Unix domain socket to open
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void thread_wdctl(void *arg)
{
    int fd;
    int *params;
    char *sock_name;
    struct sockaddr_un sa_un;
    int result;
    pthread_t tid;
    socklen_t len;

    debug(LOG_DEBUG, "Starting wdctl.");

    sock_name = (char *)arg;
    debug(LOG_DEBUG, "Socket name: %s", sock_name);

    debug(LOG_DEBUG, "Creating socket");
    wdctl_socket_server = create_unix_socket(sock_name);
    if (-1 == wdctl_socket_server) {
        termination_handler(0);
    }

    while (1) {
        len = sizeof(sa_un);
        memset(&sa_un, 0, len);
        if ((fd = accept(wdctl_socket_server, (struct sockaddr *)&sa_un, &len)) == -1) {
            debug(LOG_ERR, "Accept failed on control socket: %s", strerror(errno));
        } else {
            debug(LOG_DEBUG, "Accepted connection on wdctl socket %d (%s)", fd, sa_un.sun_path);
            params = safe_malloc(sizeof(int));
            *params = fd;
            result = pthread_create(&tid, NULL, &thread_wdctl_handler, (void *)params);
            if (result != 0) {
                debug(LOG_ERR, "FATAL: Failed to create a new thread (wdctl handler) - exiting");
                termination_handler(0);
            }
            pthread_detach(tid);
        }
    }
}

static void* thread_wdctl_handler(void *arg)
{
    int fd;
    int done=0;
    char request[MAX_BUF]={0};
    size_t read_bytes=0;
    size_t i;
    ssize_t len;

    debug(LOG_DEBUG, "Entering thread_wdctl_handler....");

    fd = *((int *)arg);
    free(arg);
    debug(LOG_DEBUG, "Read bytes and stuff from %d", fd);

    /* Read.... */
    while (!done && read_bytes < (sizeof(request) - 1)) {
        len = read(fd, request + read_bytes, sizeof(request) - read_bytes);
        /* Have we gotten a command yet? */
        for (i = read_bytes; i < (read_bytes + (size_t) len); i++) {
            if (request[i] == '\r' || request[i] == '\n') {
                request[i] = '\0';
                done = 1;
            }
        }

        /* Increment position */
        read_bytes += (size_t) len;
    }

    if (!done) {
        debug(LOG_ERR, "Invalid wdctl request.");
        shutdown(fd, 2);
        close(fd);
        pthread_exit(NULL);
    }

    debug(LOG_INFO, "Request received: [%s]", request);

    if (strncmp(request, "pass", 4) == 0) {
        wdctl_pass(fd, (request + 5));
    } else if (strncmp(request, "reset", 5) == 0) {
        wdctl_reset(fd, (request + 6));
    } else if (strncmp(request, "status", 6) == 0) {
        wdctl_status(fd);
    } else if (strncmp(request, "statistics", 4) == 0) {
        wdctl_statistics(fd);
    } else if (strncmp(request, "stop", 4) == 0) {
        wdctl_stop(fd);
    } else if (strncmp(request, "restart", 7) == 0) {
        wdctl_restart(fd);
    } else if (strncmp(request, "debug", 5) == 0) {
        wdctl_debug(fd, (request + 6));
    }else {
        debug(LOG_ERR, "Request was not understood!");
    }

    shutdown(fd, 2);
    close(fd);
    debug(LOG_DEBUG, "Exiting thread_wdctl_handler....");

    return NULL;
}

static int write_to_socket(int fd, char *text, size_t len)
{
    ssize_t retval;
    size_t written;

    written = 0;
    while (written < len) {
        retval = write(fd, (text + written), len - written);
        if (retval == -1) {
            debug(LOG_CRIT, "Failed to write client data to child: %s", strerror(errno));
            return 0;
        } else {
            written += retval;
        }
    }
    return 1;
}

static void wdctl_pass(int fd, const char *arg)
{
    t_client *node;
    char buf[MAX_BUF]={0};
    char ip[MAX_IP_ADDR_LEN]={0};
    char mac[MAX_MAC_ADDR_LEN]={0};
    char phone[MAX_PHONE_LEN]={0};
    char token[MAX_TOKEN_LEN]={0};
    char record_id[MAX_RECORD_ID_LEN]={0};
    char* mac2=NULL;
    char* cp = buf;
    char* cp_raw=cp;
    int argc_no = 1;
    debug(LOG_DEBUG, "Entering wdctl_pass... Argument: %s (@%p)", arg, arg);
    
    strncpy(buf, arg, MAX_BUF-1);    
    while (*cp) {
        if (*cp == '&')
        {
            *cp = 0;
            if(argc_no==1)
            {
                strncpy(ip, cp_raw, MAX_IP_ADDR_LEN-1);
            }
            else if(argc_no==2)
            {
                strncpy(mac, cp_raw, MAX_MAC_ADDR_LEN-1);
            }
            else if(argc_no==3)
            {
                strncpy(phone, cp_raw, MAX_PHONE_LEN-1);
            }
            else if(argc_no==4)
            {
                strncpy(token, cp_raw, MAX_TOKEN_LEN-1);
            }
            cp++;
            argc_no++;
            cp_raw=cp;
        }
        else
        {
            cp++;
        }
    }
    strncpy(record_id, cp_raw, MAX_RECORD_ID_LEN-1);

    debug(LOG_DEBUG, "Resolved parameters[Ip:%s Mac:%s Phone:%s Token:%s Record:%s]", ip, mac, phone, token, record_id);
    
    mac2 = arp_get(ip);
    if(NULL == mac2 || 0 != strcmp(mac, mac2))
    {
        debug(LOG_ERR, "Retrieve error Mac of Ip %s: %s, but real Mac %s", ip, mac, mac2);
        if(mac2) free(mac2);
        write_to_socket(fd, "No", 2);
        debug(LOG_DEBUG, "Exiting wdctl_pass...");
        return;
    }
    free(mac2);
    
    LOCK_CLIENT_LIST();
    if ((node = client_list_find(ip, mac)) == NULL)
    {
        debug(LOG_DEBUG, "wdctl_pass new client %s", ip);
        node = client_list_add(ip, mac, phone, get_terminal_type(NULL), record_id, token);
    }
    else
    {
        debug(LOG_DEBUG, "wdctl_pass client %s, which is already in the client list", node->ip);
        client_update(node, phone, get_terminal_type(NULL), record_id, token, get_millisecond());
    }

    if(node)
    {
        if(process_auth_result(NULL, NULL, node, AUTH_ALLOWED))
            inner_stt.loginByCmdLine++;
        UNLOCK_CLIENT_LIST();        
        write_to_socket(fd, "Yes", 3);
    }
    else
    {
        UNLOCK_CLIENT_LIST();
        debug(LOG_ERR, "Out of resource for ip %s", ip);
    }
    debug(LOG_DEBUG, "Exiting wdctl_pass...");
}

static void wdctl_reset(int fd, const char *arg)
{
    t_client *node;

    debug(LOG_DEBUG, "Entering wdctl_reset...Argument: %s (@%p)", arg, arg);

    LOCK_CLIENT_LIST();

    /* We get the node or return... */
    if ((node = client_list_find_by_ip(arg)) != NULL) ;
    else if ((node = client_list_find_by_mac(arg)) != NULL) ;
    else {
        debug(LOG_DEBUG, "Client not found.");
        UNLOCK_CLIENT_LIST();
        write_to_socket(fd, "No", 2);   /* Error handling in fucntion sufficient. */
        debug(LOG_DEBUG, "Exiting wdctl_reset...");
        return;
    }

    debug(LOG_DEBUG, "Got node:%-10llu %-16s %-18s %-11s %-5s %-10s", 
                     node->id, node->ip, node->mac, node->phone, node->token, node->record_id);
    /* deny.... */
    if(logout_client(node, true))
        inner_stt.logoutByCmdLine++;
    UNLOCK_CLIENT_LIST();

    write_to_socket(fd, "Yes", 3);
    debug(LOG_DEBUG, "Exiting wdctl_reset...");
}

static void wdctl_status(int fd)
{
    char *status = NULL;
    size_t len = 0;

    status = get_status_text();
    len = strlen(status);
    //printf("buf len:%d\n", (int)len);
    write_to_socket(fd, status, len);   /* XXX Not handling error because we'd just print the same log line. */

    free(status);
}

static void wdctl_statistics(int fd)
{
    char *stt = NULL;
    size_t len = 0;

    stt = get_statistics_text();
    len = strlen(stt);

    write_to_socket(fd, stt, len);   /* XXX Not handling error because we'd just print the same log line. */

    free(stt);
}

/** A bit of an hack, self kills.... */
/* coverity[+kill] */
static void wdctl_stop(int fd)
{
    pid_t pid;

    pid = getpid();
    kill(pid, SIGINT);
}

static void wdctl_restart(int afd)
{
    int sock, fd;
    char *sock_name;
    T_CONFIG *conf = NULL;
    struct sockaddr_un sa_un;
    t_client *client;
    t_client *worklist;
    char *tempstring = NULL;
    pid_t pid;
    socklen_t len;

    conf = config_get_config();

    debug(LOG_NOTICE, "Will restart myself");

    /* First, prepare the internal socket */
    sock_name = conf->internal_sock;
    debug(LOG_DEBUG, "Socket name: %s", sock_name);

    debug(LOG_DEBUG, "Creating socket");
    sock = create_unix_socket(sock_name);
    if (-1 == sock) {
        return;
    }

    /*
     * The internal socket is ready, fork and exec ourselves
     */
    debug(LOG_DEBUG, "Forking in preparation for exec()...");
    pid = safe_fork();
    if (pid > 0) {
        /* Parent */

        /* Wait for the child to connect to our socket : */
        debug(LOG_DEBUG, "Waiting for child to connect on internal socket");
        len = sizeof(sa_un);
        if ((fd = accept(sock, (struct sockaddr *)&sa_un, &len)) == -1) {
            debug(LOG_ERR, "Accept failed on internal socket: %s", strerror(errno));
            close(sock);
            return;
        }

        close(sock);

        debug(LOG_DEBUG, "Received connection from child.  Sending them all existing clients");

        /* The child is connected. Send them over the socket the existing clients */
        LOCK_CLIENT_LIST();
        client_list_dup(&worklist);
        UNLOCK_CLIENT_LIST();
        client = worklist;
        while (client) {
            /* Send this client */
            safe_asprintf(&tempstring,
                          "CLIENT|ip=%s|mac=%s|phone=%s|type=%s|token=%s|record_id=%s|fw_connection_state=%u|pass_time=%llu|inComingPkt=%llu|inComingByt=%llu|outGoingPkt=%llu|outGoingByt=%llu|last_updated=%lu\n",
                          client->ip, client->mac, client->phone, client->type, client->token, client->record_id, 
                          client->fw_connection_state, client->pass_time,
                          client->counters.inComingPkt, client->counters.inComingByt, 
                          client->counters.outGoingPkt, client->counters.outGoingByt,
                          client->counters.last_updated);
            debug(LOG_DEBUG, "Sending to child client data: %s", tempstring);
            write_to_socket(fd, tempstring, strlen(tempstring));        /* XXX Despicably not handling error. */
            client = client->next;
        }
        client_list_destroy(worklist);
        
        close(fd);
        
        debug(LOG_INFO, "Sent all existing clients to child.  Committing suicide!");

        shutdown(afd, 2);
        close(afd);

        /* Our job in life is done. Commit suicide! */
        wdctl_stop(afd);
    }
    else 
    {
        /* Child */
        close(wdctl_socket_server);
        close(sock);
        close_icmp_socket();
        shutdown(afd, 2);
        close(afd);
        debug(LOG_NOTICE, "Re-executing myself (%s)", restartargv[0]);
        setsid();
        execvp(restartargv[0], restartargv);
        /* If we've reached here the exec() failed - die quickly and silently */
        debug(LOG_ERR, "I failed to re-execute myself: %s", strerror(errno));
        debug(LOG_ERR, "Exiting without cleanup");
        exit(1);
    }
}

static void wdctl_debug(int fd, const char *arg)
{
    int level;
    debug(LOG_DEBUG, "Entering wdctl_debug...Argument: %s (@%p)", arg, arg);

    level = atoi(arg);
    if(level>=LOG_EMERG && level<=LOG_TRACE)
    {
        debugconf.debuglevel = level;
    }
    debug(LOG_DEBUG, "Exiting wdctl_debug...");
}


