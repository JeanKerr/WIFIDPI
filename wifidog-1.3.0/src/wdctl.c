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
/** @file wdctl.c
    @brief Monitoring and control of process, client part
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#include "common.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "wdctl.h"

static s_wdconfig wdconfig;

static void usage2(char* process);
static void init_config(void);
static void parse_commandline2(int, char **);
static int connect_to_server(const char *);
static size_t send_request(int, const char *);
static void wdctl_pass(void);
static void wdctl_reset(void);
static void wdctl_status(void);
static void wdctl_statistics(void);
static void wdctl_stop(void);
static void wdctl_restart(void);
static void wdctl_debug(void);
static void wdctl_dpi(void);

/** @internal
 * @brief Print usage
 *
 * Prints usage, called when wdctl is run with -h or with an unknown option
 */
static void usage2(char* process)
{
    fprintf(stdout, "Usage: %s [options] command [arguments]\n", process);
    fprintf(stdout, "\n");
    fprintf(stdout, "options:\n");
    fprintf(stdout, "  -s <path>         Path to the socket(maximum 255 bytes)\n");
    fprintf(stdout, "  -h                Print usage\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "commands:\n");
    fprintf(stdout, "  login [ip mac phone token record_id]  Set the specified mac or ip connection active\n");
    fprintf(stdout, "  logout [mac|ip]                       Reset the specified mac or ip connection\n");
    fprintf(stdout, "  status                                Obtain the status of controlled process\n");
    fprintf(stdout, "  statistics                            Obtain the inner statistics of controlled process\n");
    fprintf(stdout, "  stop                                  Stop the running controlled process\n");
    fprintf(stdout, "  restart                               Re-start the running controlled process (without disconnecting active users!)\n");
    fprintf(stdout, "  debug [level]                         Set log level <0-8> of the running controlled process\n");
    fprintf(stdout, "  dpi [start|stop|statistics]           Set dpi command\n");
    fprintf(stdout, "\n");
}

/** @internal
 *
 * Init default values in config struct
 */
static void init_config(void)
{
    memset(&wdconfig, 0, sizeof(wdconfig));
    strncpy(wdconfig.socket, DEFAULT_SOCK, WDCTL_MAX_PATH_LEN-1);
    wdconfig.command = WDCTL_UNDEF;
}

/** @internal
 *
 * Uses getopt() to parse the command line and set configuration values
 */
void parse_commandline2(int argc, char **argv)
{
    extern int optind;
    int c;
    int i;
    int dgbLevel = 0;
    while (-1 != (c = getopt(argc, argv, "s:h"))) {
        switch (c) {
        case 'h':
            usage2(argv[0]);
            exit(1);
            break;

        case 's':
            if (optarg) {
                if(strlen(optarg) > WDCTL_MAX_PATH_LEN-1)
                {
                    usage2(argv[0]);
                    exit(1);
                }
                else
                {
                    memset(wdconfig.socket, 0, sizeof(wdconfig.socket));
                    strncpy(wdconfig.socket, optarg, WDCTL_MAX_PATH_LEN-1);
                }
            }
            break;
        default:
            usage2(argv[0]);
            exit(1);
            break;
        }
    }

    if ((argc - optind) <= 0) {
        usage2(argv[0]);
        exit(1);
    }

    if (strcmp(*(argv + optind), "login") == 0)
    {
        wdconfig.command = WDCTL_PASS;
        if ((argc - (optind + 5)) <= 0) 
        {
            fprintf(stderr, "wdctl: Error: You must specify 5 parameters\n");
            usage2(argv[0]);
            exit(1);
        }
        memset(wdconfig.param, 0, sizeof(wdconfig.param));
        for(i=0; i<5; i++)
            strncpy(wdconfig.param[i], *(argv + optind + 1 + i), WDCTL_MAX_PARAM_LEN-1);
    }
    else if (strcmp(*(argv + optind), "logout") == 0) 
    {
        wdconfig.command = WDCTL_KICK;
        if ((argc - (optind + 1)) <= 0) 
        {
            fprintf(stderr, "wdctl: Error: You must specify an IP or a Mac address to reset\n");
            usage2(argv[0]);
            exit(1);
        }
        memset(wdconfig.param, 0, sizeof(wdconfig.param));
        strncpy(wdconfig.param[0], *(argv + optind + 1), WDCTL_MAX_PARAM_LEN-1);
    } 
    else if (strcmp(*(argv + optind), "status") == 0)
    {
        wdconfig.command = WDCTL_STATUS;
    } 
    else if (strcmp(*(argv + optind), "statistics") == 0) 
    {
        wdconfig.command = WDCTL_STATISTICS;
    } 
    else if (strcmp(*(argv + optind), "stop") == 0)
    {
        wdconfig.command = WDCTL_STOP;
    } 
    else if (strcmp(*(argv + optind), "restart") == 0)
    {
        wdconfig.command = WDCTL_RESTART;
    }
    else if (strcmp(*(argv + optind), "debug") == 0)
    {
        wdconfig.command = WDCTL_DEBUG;
        if ((argc - (optind + 1)) <= 0) 
        {
            fprintf(stderr, "wdctl: Error: You must specify debug level <0-8>\n");
            usage2(argv[0]);
            exit(1);
        }
        memset(wdconfig.param, 0, sizeof(wdconfig.param));
        strncpy(wdconfig.param[0], *(argv + optind + 1), WDCTL_MAX_PARAM_LEN-1);
        dgbLevel = atoi(wdconfig.param[0]);
        if(dgbLevel > 8 || dgbLevel < 0)
        {
            fprintf(stderr, "wdctl: Error: You must specify debug level <0-8>\n");
            usage2(argv[0]);
            exit(1);
        }
    }
    else if (strcmp(*(argv + optind), "dpi") == 0)
    {
        wdconfig.command = WDCTL_DPI;
        if ((argc - (optind + 1)) <= 0) 
        {
            fprintf(stderr, "wdctl: Error: You must specify 1 dpi parameter\n");
            usage2(argv[0]);
            exit(1);
        }
        else
        {
            if (strncmp(*(argv + optind + 1), "start", 5)
                || strncmp(*(argv + optind + 1), "stop", 4)
                || strncmp(*(argv + optind + 1), "statistics", 10))
            {
				fprintf(stderr, "wdctl: Error dpi parameter \n");
				usage2(argv[0]);
				exit(1);
            }
        }
        memset(wdconfig.param, 0, sizeof(wdconfig.param));
        strncpy(wdconfig.param[0], *(argv + optind + 1), WDCTL_MAX_PARAM_LEN-1);
    }
    else
    {
        fprintf(stderr, "wdctl: Error: Invalid command \"%s\"\n", *(argv + optind));
        usage2(argv[0]);
        exit(1);
    }
}

static int connect_to_server(const char *sock_name)
{
    int sock;
    struct sockaddr_un sa_un;

    /* Connect to socket */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "wdctl: could not get socket (Error: %s)\n", strerror(errno));
        exit(1);
    }
    memset(&sa_un, 0, sizeof(sa_un));
    sa_un.sun_family = AF_UNIX;
    strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));

    if (connect(sock, (struct sockaddr *)&sa_un, strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
        fprintf(stderr, "wdctl: controlled process probably not started (Error: %s)\n", strerror(errno));
        exit(1);
    }

    return sock;
}

static size_t send_request(int sock, const char *request)
{
    size_t len;
    ssize_t written;

    len = 0;
    while (len != strlen(request)) {
        written = write(sock, (request + len), strlen(request) - len);
        if (written == -1) {
            fprintf(stderr, "Write to controlled process failed: %s\n", strerror(errno));
            exit(1);
        }
        len += (size_t) written;
    }

    return len;
}

void wdctl_pass(void)
{
    int sock;
    int i;
    char buffer[WDCTL_MAX_BUF];
    char request[WDCTL_MAX_CMD_LEN+WDCTL_MAX_PARAM_NUM*WDCTL_MAX_PARAM_LEN]={0};
    size_t len;
    ssize_t rlen;

    sock = connect_to_server(wdconfig.socket);

    strncpy(request, "pass ", WDCTL_MAX_CMD_LEN-1);
    for(i=0; i<WDCTL_MAX_PARAM_NUM; i++)
    {
        strncat(request, wdconfig.param[i], WDCTL_MAX_PARAM_LEN-1);
        if(i!=WDCTL_MAX_PARAM_NUM-1)
            strncat(request, "&", 1);
    }
    strncat(request, "\r\n\r\n", (WDCTL_MAX_CMD_LEN+WDCTL_MAX_PARAM_NUM*WDCTL_MAX_PARAM_LEN - 1));

    send_request(sock, request);

    len = 0;
    memset(buffer, 0, sizeof(buffer));
    while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len), (sizeof(buffer) - len))) > 0)) {
        len += (size_t) rlen;
    }

    if (strcmp(buffer, "Yes") == 0) {
        fprintf(stdout, "Connection %s successfully login.\n", wdconfig.param[0]);
    } else if (strcmp(buffer, "No") == 0) {
        fprintf(stdout, "Connection %s login failed.\n", wdconfig.param[0]);
    } else {
        fprintf(stderr, "wdctl: Error: got an abnormal " "reply.\n");
    }

    shutdown(sock, 2);
    close(sock);
}

void wdctl_reset(void)
{
    int sock;
    char buffer[WDCTL_MAX_BUF];
    char request[WDCTL_MAX_CMD_LEN+WDCTL_MAX_PARAM_NUM*WDCTL_MAX_PARAM_LEN]={0};
    size_t len;
    ssize_t rlen;

    sock = connect_to_server(wdconfig.socket);

    strncpy(request, "reset ", WDCTL_MAX_CMD_LEN-1);
    strncat(request, wdconfig.param[0], WDCTL_MAX_PARAM_LEN-1);
    strncat(request, "\r\n\r\n", WDCTL_MAX_CMD_LEN+WDCTL_MAX_PARAM_NUM*WDCTL_MAX_PARAM_LEN - 1);

    send_request(sock, request);

    len = 0;
    memset(buffer, 0, sizeof(buffer));
    while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len), (sizeof(buffer) - len))) > 0)) {
        len += (size_t) rlen;
    }

    if (strcmp(buffer, "Yes") == 0) {
        fprintf(stdout, "Connection %s successfully reset.\n", wdconfig.param[0]);
    } else if (strcmp(buffer, "No") == 0) {
        fprintf(stdout, "Connection %s was not active.\n", wdconfig.param[0]);
    } else {
        fprintf(stderr, "wdctl: Error: got an abnormal " "reply.\n");
    }

    shutdown(sock, 2);
    close(sock);
}

static void wdctl_status(void)
{
    int sock;
    char buffer[WDCTL_MAX_BUF];
    char request[WDCTL_MAX_CMD_LEN]={0};
    ssize_t len;

    sock = connect_to_server(wdconfig.socket);

    strncpy(request, "status\r\n\r\n", WDCTL_MAX_CMD_LEN-1);

    send_request(sock, request);

    // -1: need some space for \0!
    while ((len = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);
}

static void wdctl_statistics(void)
{
    int sock;
    char buffer[WDCTL_MAX_BUF];
    char request[WDCTL_MAX_CMD_LEN]={0};
    ssize_t len;

    sock = connect_to_server(wdconfig.socket);

    strncpy(request, "statistics\r\n\r\n", WDCTL_MAX_CMD_LEN-1);

    send_request(sock, request);

    // -1: need some space for \0!
    while ((len = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);
}

static void wdctl_stop(void)
{
    int sock;
    char buffer[WDCTL_MAX_BUF];
    char request[WDCTL_MAX_CMD_LEN]={0};
    ssize_t len;

    sock = connect_to_server(wdconfig.socket);

    strncpy(request, "stop\r\n\r\n", WDCTL_MAX_CMD_LEN-1);

    send_request(sock, request);

    while ((len = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);
}

static void wdctl_restart(void)
{
    int sock;
    char buffer[WDCTL_MAX_BUF];
    char request[WDCTL_MAX_CMD_LEN]={0};
    ssize_t len;

    sock = connect_to_server(wdconfig.socket);

    strncpy(request, "restart\r\n\r\n", WDCTL_MAX_CMD_LEN-1);

    send_request(sock, request);

    while ((len = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);
}

static void wdctl_debug(void)
{
    int sock;
    char buffer[WDCTL_MAX_BUF];
    char request[WDCTL_MAX_CMD_LEN]={0};
    ssize_t len;

    sock = connect_to_server(wdconfig.socket);

    strncpy(request, "debug ", WDCTL_MAX_CMD_LEN-1);
    strncat(request, wdconfig.param[0], WDCTL_MAX_PARAM_LEN-1);
    strncat(request, "\r\n\r\n", WDCTL_MAX_CMD_LEN+WDCTL_MAX_PARAM_NUM*WDCTL_MAX_PARAM_LEN - 1);

    send_request(sock, request);

    while ((len = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);
}

static void wdctl_dpi(void)
{
    int sock;
    char buffer[WDCTL_MAX_BUF];
    char request[WDCTL_MAX_CMD_LEN]={0};
    ssize_t len;

    sock = connect_to_server(wdconfig.socket);

    strncpy(request, "dpi ", WDCTL_MAX_CMD_LEN-1);
    strncat(request, wdconfig.param[0], WDCTL_MAX_PARAM_LEN-1);
    strncat(request, "\r\n\r\n", WDCTL_MAX_CMD_LEN+WDCTL_MAX_PARAM_NUM*WDCTL_MAX_PARAM_LEN - 1);

    send_request(sock, request);

    while ((len = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);
}

int main(int argc, char **argv)
{

    /* Init configuration */
    init_config();
    parse_commandline2(argc, argv);

    switch (wdconfig.command) {
    case WDCTL_PASS:
        wdctl_pass();
        break;

    case WDCTL_KICK:
        wdctl_reset();
        break;

    case WDCTL_STATUS:
        wdctl_status();
        break;
        
    case WDCTL_STATISTICS:
        wdctl_statistics();
        break;
    
    case WDCTL_STOP:
        wdctl_stop();
        break;

    case WDCTL_RESTART:
        wdctl_restart();
        break;

    case WDCTL_DEBUG:
        wdctl_debug();
        break;
    case WDCTL_DPI:
        wdctl_dpi();
        break;

    default:
        /* XXX NEVER REACHED */
        fprintf(stderr, "Oops\n");
        exit(1);
        break;
    }
    exit(0);
}

