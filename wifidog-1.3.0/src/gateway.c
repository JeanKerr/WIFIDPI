/* vim: set et sw=4 ts=4 sts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free:Software Foundation; either version 2 of   *
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

/** @internal
  @file gateway.c
  @brief Main loop
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
 */

#include "common.h"

/* for wait() */
#include <sys/wait.h>

/* for unix socket communication*/
#include <sys/socket.h>
#include <sys/un.h>

#include "httpd.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "gateway.h"
#include "firewall.h"
#include "commandline.h"
#include "auth.h"
#include "http.h"
#include "client_list.h"
#include "wdctl_thread.h"
#include "agent_thread.h"
#include "portal_thread.h"
#include "dpi_thread.h"
#include "util.h"

#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <link.h>
#include <dlfcn.h>

#include <ucontext.h>
 
#define sigsegv_outp(x, ...)    debug(LOG_INFO, x"\n", ##__VA_ARGS__)  
  
#if (defined __x86_64__)  
    #define REGFORMAT   "%016llx"      
#elif (defined __i386__)  
    #define REGFORMAT   "%08x"  
#elif (defined __arm__)  
    #define REGFORMAT   "%lx"  
#endif 


/** XXX Ugly hack 
 * We need to remember the thread IDs of threads that simulate wait with pthread_cond_timedwait
 * so we can explicitly kill them in the termination handler
 */
static pthread_t tid_fw_counter = 0;
static pthread_t tid_comm_agent = 0;
static pthread_t tid_portal_update = 0;
static pthread_t tid_version_update = 0;
static pthread_t tid_client_timedout = 0;
static pthread_t tid_webserver_http_listenner = 0;
static pthread_t tid_webserver_https_listenner = 0;
static pthread_t tid_extwebserver_listenner = 0;
static pthread_t tid_dpi_main = 0;


time_t started_time = 0;

/* The internal web server */
httpd* webserver = NULL;
httpd* webserverhttps = NULL;
httpd* extwebserver = NULL;
T_DPI_PARAM gtDpiParam;

/** @brief Get IP/MAC address of external interface */
bool get_ext_iface_name(char* extPortBuf, int bufLen);

void writeExcpInfo(const char *format, ...);

/* Appends -x, the current PID, and NULL to restartargv
 * see parse_commandline in commandline.c for details
 *
 * Why is restartargv global? Shouldn't it be at most static to commandline.c
 * and this function static there? -Alex @ 8oct2006
 */
void append_x_restartargv(void)
{
    int i;

    for (i = 0; restartargv[i]; i++) ;

    restartargv[i++] = safe_strdup("-x");
    safe_asprintf(&(restartargv[i++]), "%d", getpid());
}

/* @internal
 * @brief During gateway restart, connects to the parent process via the internal socket
 * Downloads from it the active client list
 */
void get_clients_from_parent(void)
{
    int sock;
    struct sockaddr_un sa_un;
    T_CONFIG *config = NULL;
    char linebuffer[MAX_BUF];
    int len = 0;
    char *running1 = NULL;
    char *running2 = NULL;
    char *token1 = NULL;
    char *token2 = NULL;
    char onechar;
    char *command = NULL;
    char *key = NULL;
    char *value = NULL;
    t_client *client = NULL;

    config = config_get_config();

    debug(LOG_INFO, "Connecting to parent to download clients");

    /* Connect to socket */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    /* XXX An attempt to quieten coverity warning about the subsequent connect call:
     * Coverity says: "sock is apssed to parameter that cannot be negative"
     * Although connect expects a signed int, coverity probably tells us that it shouldn't
     * be negative */
    if (sock < 0) {
        debug(LOG_ERR, "Could not open socket (%s) - client list not downloaded", strerror(errno));
        return;
    }
    memset(&sa_un, 0, sizeof(sa_un));
    sa_un.sun_family = AF_UNIX;
    strncpy(sa_un.sun_path, config->internal_sock, (sizeof(sa_un.sun_path) - 1));

    if (connect(sock, (struct sockaddr *)&sa_un, strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
        debug(LOG_ERR, "Failed to connect to parent (%s) - client list not downloaded", strerror(errno));
        close(sock);
        return;
    }

    debug(LOG_INFO, "Connected to parent.  Downloading clients");

    LOCK_CLIENT_LIST();

    command = NULL;
    memset(linebuffer, 0, sizeof(linebuffer));
    len = 0;
    client = NULL;
    /* Get line by line */
    while (read(sock, &onechar, 1) == 1) {
        if (onechar == '\n') {
            /* End of line */
            onechar = '\0';
        }
        linebuffer[len++] = onechar;

        if (!onechar) {
            /* We have a complete entry in linebuffer - parse it */
            debug(LOG_DEBUG, "Received from parent: [%s]", linebuffer);
            running1 = linebuffer;
            while ((token1 = strsep(&running1, "|")) != NULL) {
                if (!command) {
                    /* The first token is the command */
                    command = token1;
                } else {
                    /* Token1 has something like "foo=bar" */
                    running2 = token1;
                    key = value = NULL;
                    while ((token2 = strsep(&running2, "=")) != NULL) {
                        if (!key) {
                            key = token2;
                        } else if (!value) {
                            value = token2;
                        }
                    }
                }

                if (strcmp(command, "CLIENT") == 0) {
                    /* This line has info about a client in the client list */
                    if (NULL == client) {
                        /* Create a new client struct */
                        client = client_alloc();
                    }
                }

                /* XXX client check to shut up clang... */
                if (key && value && client) {
                    if (strcmp(command, "CLIENT") == 0) {
                        /* Assign the key into the appropriate slot in the connection structure */
                        if (strcmp(key, "ip") == 0) {
                            CLIENT_COPY_FIELD(client, ip, value);
                        } else if (strcmp(key, "mac") == 0) {
                            CLIENT_COPY_FIELD(client, mac, value);
                        } else if (strcmp(key, "phone") == 0) {
                            CLIENT_COPY_FIELD(client, phone, value);
                        } else if (strcmp(key, "type") == 0) {
                            CLIENT_COPY_FIELD(client, type, value);
                        } else if (strcmp(key, "token") == 0) {
                            CLIENT_COPY_FIELD(client, token, value);
                        } else if (strcmp(key, "record_id") == 0) {
                            CLIENT_COPY_FIELD(client, record_id, value);
                        } else if (strcmp(key, "fw_connection_state") == 0) {
                            client->fw_connection_state = atoi(value);
                        } else if (strcmp(key, "pass_time") == 0) {
                            client->pass_time = atoll(value);
                        } else if (strcmp(key, "inComingPkt") == 0) {
                            client->counters.inComingPktHistory = (unsigned long long)atoll(value);
                            client->counters.inComingPkt = client->counters.inComingPktHistory;
                            client->counters.inComingPktDelta = 0;
                        } else if (strcmp(key, "inComingByt") == 0) {
                            client->counters.inComingBytHistory = (unsigned long long)atoll(value);
                            client->counters.inComingByt = client->counters.inComingBytHistory;
                            client->counters.inComingBytDelta = 0;
                        } else if (strcmp(key, "outGoingPkt") == 0) {
                            client->counters.outGoingPktHistory = (unsigned long long)atoll(value);
                            client->counters.outGoingPkt = client->counters.outGoingPktHistory;
                            client->counters.outGoingPktDelta = 0;
                        } else if (strcmp(key, "outGoingByt") == 0) {
                            client->counters.outGoingBytHistory = (unsigned long long)atoll(value);
                            client->counters.outGoingByt = client->counters.outGoingBytHistory;
                            client->counters.outGoingBytDelta = 0;
                        } else if (strcmp(key, "last_updated") == 0) {
                            client->counters.last_updated = atol(value);
                        } else {
                            debug(LOG_NOTICE, "I don't know how to inherit key [%s] value [%s] from parent", key,
                                  value);
                        }
                    }
                }
            }

            /* End of parsing this command */
            if (client) {
                client_list_insert_client(client);
            }

            /* Clean up */
            command = NULL;
            memset(linebuffer, 0, sizeof(linebuffer));
            len = 0;
            client = NULL;
        }
    }

    UNLOCK_CLIENT_LIST();
    debug(LOG_INFO, "Client list downloaded successfully from parent");

    close(sock);
}

/**@internal
 * @brief Handles SIGCHLD signals to avoid zombie processes
 *
 * When a child process exits, it causes a SIGCHLD to be sent to the
 * process. This handler catches it and reaps the child process so it
 * can exit. Otherwise we'd get zombie processes.
 */
void sigchld_handler(int s)
{
    int status;
    pid_t rc;

    debug(LOG_TRACE, "Handler for SIGCHLD called. Trying to reap a child");

    rc = waitpid(-1, &status, WNOHANG);

    debug(LOG_TRACE, "Handler for SIGCHLD reaped child PID %d", rc);
}

/** Exits cleanly after cleaning up the firewall.  
 *  Use this function anytime you need to exit after firewall initialization.
 *  @param s Integer that is really a boolean, true means voluntary exit, 0 means error.
 */
extern void dpisigproc(int sig);
void termination_handler(int s)
{
    static pthread_mutex_t sigterm_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_t self = pthread_self();

    debug(LOG_INFO, "Handler for termination caught signal %d", s);

    /* Makes sure we only call fw_destroy() once. */
    if (pthread_mutex_trylock(&sigterm_mutex)) {
        debug(LOG_INFO, "Another thread already began global termination handler. I'm exiting");
        pthread_exit(NULL);
    } else {
        debug(LOG_INFO, "Cleaning up and exiting");
    }

    debug(LOG_INFO, "Flushing firewall rules...");
    fw_destroy();
    dpisigproc(s);
    /* XXX Hack
     * Aparently pthread_cond_timedwait under openwrt prevents signals (and therefore
     * termination handler) from happening so we need to explicitly kill the threads 
     * that use that
     */
    if (tid_fw_counter && self != tid_fw_counter) {
        debug(LOG_INFO, "Explicitly killing the fw_counter thread");
        pthread_kill(tid_fw_counter, SIGKILL);
    }
    if (tid_comm_agent && self != tid_comm_agent) {
        debug(LOG_INFO, "Explicitly killing the comm_agent thread");
        pthread_kill(tid_comm_agent, SIGKILL);
    }
    if (tid_portal_update && self != tid_portal_update) {
        debug(LOG_INFO, "Explicitly killing the portal_update thread");
        pthread_kill(tid_portal_update, SIGKILL);
    }
    if (tid_version_update && self != tid_version_update) {
        debug(LOG_INFO, "Explicitly killing the version_update thread");
        pthread_kill(tid_version_update, SIGKILL);
    }
    if (tid_client_timedout && self != tid_client_timedout) {
        debug(LOG_INFO, "Explicitly killing the client_timedout thread");
        pthread_kill(tid_client_timedout, SIGKILL);
    }
    if (tid_webserver_http_listenner && self != tid_webserver_http_listenner) {
        debug(LOG_INFO, "Explicitly killing the webserver_http_listenner thread");
        pthread_kill(tid_webserver_http_listenner, SIGKILL);
    }
    if (tid_webserver_https_listenner && self != tid_webserver_https_listenner) {
        debug(LOG_INFO, "Explicitly killing the webserver_https_listenner thread");
        pthread_kill(tid_webserver_https_listenner, SIGKILL);
    }
    if (tid_extwebserver_listenner && self != tid_extwebserver_listenner) {
        debug(LOG_INFO, "Explicitly killing the extwebserver_listenner thread");
        pthread_kill(tid_extwebserver_listenner, SIGKILL);
    }
    if (tid_dpi_main && self != tid_dpi_main) {
        debug(LOG_INFO, "Explicitly killing the dpi_main thread");
        pthread_kill(tid_extwebserver_listenner, SIGKILL);
    }

    debug(LOG_NOTICE, "Exiting...");
    rhy_exit(s == 0 ? 1 : 0);
}

#if (defined __arm__)
static void print_reg(ucontext_t *uc)   
{  
#if (defined __x86_64__) || (defined __i386__)  
    int i;  
    for (i = 0; i < NGREG; i++) {  
        writeExcpInfo("reg[%02d]: 0x"REGFORMAT, i, uc->uc_mcontext.gregs[i]);  
    }  
#elif (defined __arm__)  
    writeExcpInfo("reg[%02d]     = 0x"REGFORMAT, 0, uc->uc_mcontext.arm_r0);  
    writeExcpInfo("reg[%02d]     = 0x"REGFORMAT, 1, uc->uc_mcontext.arm_r1);  
    writeExcpInfo("reg[%02d]     = 0x"REGFORMAT, 2, uc->uc_mcontext.arm_r2);  
    writeExcpInfo("reg[%02d]     = 0x"REGFORMAT, 3, uc->uc_mcontext.arm_r3);  
    writeExcpInfo("reg[%02d]     = 0x"REGFORMAT, 4, uc->uc_mcontext.arm_r4);  
    writeExcpInfo("reg[%02d]     = 0x"REGFORMAT, 5, uc->uc_mcontext.arm_r5);  
    writeExcpInfo("reg[%02d]     = 0x"REGFORMAT, 6, uc->uc_mcontext.arm_r6);  
    writeExcpInfo("reg[%02d]     = 0x"REGFORMAT, 7, uc->uc_mcontext.arm_r7);  
    writeExcpInfo("reg[%02d]     = 0x"REGFORMAT, 8, uc->uc_mcontext.arm_r8);  
    writeExcpInfo("reg[%02d]     = 0x"REGFORMAT, 9, uc->uc_mcontext.arm_r9);  
    writeExcpInfo("reg[%02d]     = 0x"REGFORMAT, 10, uc->uc_mcontext.arm_r10);  
    writeExcpInfo("FP        = 0x"REGFORMAT, uc->uc_mcontext.arm_fp);  
    writeExcpInfo("IP        = 0x"REGFORMAT, uc->uc_mcontext.arm_ip);  
    writeExcpInfo("SP        = 0x"REGFORMAT, uc->uc_mcontext.arm_sp);  
    writeExcpInfo("LR        = 0x"REGFORMAT, uc->uc_mcontext.arm_lr);  
    writeExcpInfo("PC        = 0x"REGFORMAT, uc->uc_mcontext.arm_pc);  
    writeExcpInfo("CPSR      = 0x"REGFORMAT, uc->uc_mcontext.arm_cpsr);  
    writeExcpInfo("Fault Address = 0x"REGFORMAT, uc->uc_mcontext.fault_address);  
    writeExcpInfo("Trap no       = 0x"REGFORMAT, uc->uc_mcontext.trap_no);  
    writeExcpInfo("Err Code  = 0x"REGFORMAT, uc->uc_mcontext.error_code);  
    writeExcpInfo("Old Mask  = 0x"REGFORMAT, uc->uc_mcontext.oldmask);  
#endif  
} 

static void print_call_link(ucontext_t *uc)   
{  
    int i = 0;  
    void **frame_pointer = (void **)NULL;  
    void *return_address = NULL;  
    Dl_info dl_info = {0};  
  
#if (defined __i386__)  
    frame_pointer = (void **)uc->uc_mcontext.gregs[REG_EBP];  
    return_address = (void *)uc->uc_mcontext.gregs[REG_EIP];  
#elif (defined __x86_64__)  
    frame_pointer = (void **)uc->uc_mcontext.gregs[10];  //gregs[REG_RBP]
    return_address = (void *)uc->uc_mcontext.gregs[16];  //gregs[REG_RIP]
#elif (defined __arm__)  
/* sigcontext_t on ARM: 
        unsigned long trap_no; 
        unsigned long error_code; 
        unsigned long oldmask; 
        unsigned long arm_r0; 
        ... 
        unsigned long arm_r10; 
        unsigned long arm_fp; 
        unsigned long arm_ip; 
        unsigned long arm_sp; 
        unsigned long arm_lr; 
        unsigned long arm_pc; 
        unsigned long arm_cpsr; 
        unsigned long fault_address; 
*/  
    frame_pointer = (void **)uc->uc_mcontext.arm_fp;  
    return_address = (void *)uc->uc_mcontext.arm_pc;  
#endif  
  
    writeExcpInfo("\nStack trace:");  
    while (frame_pointer && return_address) {  
        if (!dladdr(return_address, &dl_info))  break;  
        const char *sname = dl_info.dli_sname;
        /* No: return address <sym-name + offset> (filename) */  
        writeExcpInfo("%02d: %p <%s + %lu> (%s)", ++i, return_address, sname,   
            (unsigned long)return_address - (unsigned long)dl_info.dli_saddr,   
                                                    dl_info.dli_fname); 
        if (dl_info.dli_sname && !strcmp(dl_info.dli_sname, "main")) {  
            break;  
        }  
  
#if (defined __x86_64__) || (defined __i386__)  
        return_address = frame_pointer[1];  
        frame_pointer = frame_pointer[0];  
#elif (defined __arm__)  
        return_address = frame_pointer[-1];   
        frame_pointer = (void **)frame_pointer[-3];  
#endif  
    }  
    writeExcpInfo("Stack trace end.");  
} 

static void sigsegv_handler(int signo, siginfo_t *info, void *context)  
{
#if 1
    time_t ts;
    char buf[30]={0};
    char buff[MAX_TEMP_BUFFER_SIZE]={0};
    time(&ts);
    snprintf(buff, sizeof(buff)-1, "[%.24s][pid:%u] ", ctime_r(&ts, buf), getpid());

    if (context) {  
        ucontext_t *uc = (ucontext_t *)context;  

        writeExcpInfo("sigsegv_handler:%s\n--------------------", buff);
        writeExcpInfo("info.si_signo = %d", signo);  
        writeExcpInfo("info.si_errno = %d", info->si_errno);  
        writeExcpInfo("info.si_code  = %d (%s)", info->si_code,   
            (info->si_code == SEGV_MAPERR) ? "SEGV_MAPERR" : "SEGV_ACCERR");  
        writeExcpInfo("info.si_addr  = %p\n", info->si_addr);  
  
        print_reg(uc);  
        print_call_link(uc);
        writeExcpInfo("sigsegv_handler:%s\n--------------------\n\n", buff);
    }  
  
    exit(0);
#else
    char buf[1024] = {0};
    char cmd[1024] = {0};
    char* p;
    FILE *fh;
    
    snprintf(buf, sizeof(buf), "/proc/%d/cmdline", getpid());
    if(!(fh = fopen(buf, "r")))
            exit(0);
    if(!fgets(buf, sizeof(buf), fh))
            exit(0);
    fclose(fh);
    p=strchr(buf, '\n');
    if(p)
        *p = '\0';
    snprintf(cmd, sizeof(cmd), "gdb %s %d -ex=bt > ./a.txt", buf, getpid());
    system(cmd);
    
    exit(0);
#endif
}
#endif

/** @internal 
 * Registers all the signal handlers
 */
static void init_signals(void)
{
    struct sigaction sa;

    debug(LOG_DEBUG, "Initializing signal handlers");

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        rhy_exit(1);
    }

    /* Trap SIGPIPE */
    /* This is done so that when libhttpd does a socket operation on
     * a disconnected socket (i.e.: Broken Pipes) we catch the signal
     * and do nothing. The alternative is to exit. SIGPIPE are harmless
     * if not desirable.
     */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        rhy_exit(1);
    }

    sa.sa_handler = termination_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    /* Trap SIGTERM */
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        rhy_exit(1);
    }

    /* Trap SIGQUIT */
    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        rhy_exit(1);
    }

    /* Trap SIGINT */
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        rhy_exit(1);
    }
    
#if (defined __arm__)
    sa.sa_handler = (void*)sigsegv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART|SA_SIGINFO;
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        rhy_exit(1);
    }
#endif
}

void get_ext_iface_ip_until_success(char* extIpaddrBuf, int bufLen)
{
    struct timeval tval;
    unsigned int wait_cnt = 1;
    unsigned int next_print_id = 1;
    
    while(!get_ext_iface_ip(extIpaddrBuf, bufLen)) 
    {
        tval.tv_sec=5;
        tval.tv_usec=0;
        if(wait_cnt==next_print_id)
        {
            debug(LOG_INFO, "Could not get IP of external interface %s, waiting %u times: %lu seconds", 
                        extIpaddrBuf, wait_cnt, tval.tv_sec);
            next_print_id = next_print_id<SECONDS_ONE_DAY/5?next_print_id*2:SECONDS_ONE_DAY/5;
        }
        select(0,NULL,NULL,NULL,&tval);
        wait_cnt++;
    }
    debug(LOG_NOTICE, "Get IP of external interface: %s", extIpaddrBuf);
}

void httpdSetWebAccessLog(httpd* server, char* path)
{
    char FilePath[MAX_PATH_LEN]={0};
    FILE* accessFile=NULL;
    snprintf(FilePath, sizeof(FilePath)-1, "%s/%sAcess.log", path, server->name);
    accessFile = fopen(FilePath, "w");

    debug(LOG_INFO, "Set access log of %s: %s", server->name, FilePath);
    httpdSetAccessLog(server, accessFile);
}

void httpdSetWebErrorLog(httpd* server, char* path)
{
    char FilePath[MAX_PATH_LEN]={0};
    FILE* errorFile=NULL;
    snprintf(FilePath, sizeof(FilePath)-1, "%s/%sError.log", path, server->name);
    errorFile = fopen(FilePath, "w");
    debug(LOG_INFO, "Set error log of %s: %s", server->name, FilePath);
    httpdSetAccessLog(server, errorFile);
}

static FILE* pExcpFile=NULL;
void setExcpInfoSaveFile(char* path, char* filename)
{
    char FilePath[MAX_PATH_LEN]={0};
    snprintf(FilePath, sizeof(FilePath)-1, "%s/%s", path, filename);
    pExcpFile = fopen(FilePath, "w");

    debug(LOG_INFO, "Set Exception Infomation Save Path: %s", FilePath);
}

void writeExcpInfo(const char *format, ...)
{
    FILE* temp;
    va_list vlist;
    
    if (pExcpFile == NULL)
    {
        temp = stderr;
    }
    else
    {
        temp = pExcpFile;
    }

    va_start(vlist, format);
    vfprintf(temp, format, vlist);
    va_end(vlist);
    fputc('\n', temp);
    return;
}

/**@internal
 * Main execution loop 
 */
static void main_loop(void)
{
    int result = -1;
    t_auth_serv *auth_server;
    
    T_CONFIG *config = config_get_config();    
    /* Set the time when process started */
    if (!started_time)
    {
        debug(LOG_DEBUG, "Setting started_time");
        started_time = time(NULL);
    } 
    else if (started_time < MINIMUM_STARTED_TIME) 
    {
        debug(LOG_WARNING, "Detected possible clock skew - re-setting started_time");
        started_time = time(NULL);
    }
    
    /* save the pid file if needed */
    if ((!config) && (IS_NULL_CONFIG(pidfile)))
        save_pid_file(config->pidfile);

    /* If we don't have the External IP address, get it. Can't fail. */
    if(IS_NULL_CONFIG(external_address) || 0==strcmp(config->external_address, ANY_IP_ADDR_STRING)) 
    {
        if(!IS_NULL_CONFIG(external_address))
        {
            debug(LOG_DEBUG, "Finding IP of external interface %s", config->external_interface);
        }
        
        if(!IS_NULL_CONFIG(external_address))
        {
            CONFIG_CLEAR_STRING(external_address);
        }
        
        get_ext_iface_ip_until_success(config->external_address, sizeof(config->external_address));

        if(get_ext_iface_mac(config->place_code, sizeof(config->place_code)) && strncmp(config->place_code, ZERO_STR_AS_PLACE_CODE, sizeof(config->place_code)))
        {
            debug(LOG_NOTICE, "Get MAC of external interface: %s as PlaceCode", config->place_code);
        }
        else
        {
            int i = 0;
            debug(LOG_NOTICE, "Maybe external interface has no MAC, take its IP as PlaceCode");
            strncpy(config->place_code, config->external_address, MAX_IP_ADDR_LEN);
            while(i<MAX_IP_ADDR_LEN && config->place_code[i])
            {
                if('.'==config->place_code[i])
                  config->place_code[i]='D';
                i++;
            }
            config->place_code[i++]='R';
            snprintf(&config->place_code[i], sizeof(config->place_code)-1-strlen(config->place_code), "%d", rand16()%10000);
        }
    }

#if NEED_EXTERNAL_WEB_SERVICE
    debug(LOG_NOTICE, "Creating ExternalHttp web server on interface %s, %s:%d", config->external_interface, config->external_address, config->external_web_port);
    extwebserver = httpdCreate(config->external_address, config->external_web_port, "ExternalHttp");
    if (NULL == extwebserver)
    {
        debug(LOG_ERR, "Could not create ExternalHttp web server: %s", strerror(errno));
        rhy_exit(1);
    }
#endif
    /* If we don't have the Gateway IP address, get it. Can't fail. */
    if (IS_NULL_CONFIG(gw_address) || 0==strcmp(config->gw_address, ANY_IP_ADDR_STRING)) 
    {
        debug(LOG_DEBUG, "Finding IP of gw interface %s", config->gw_interface);
        if (!get_iface_ip2(config->gw_interface, config->gw_address, sizeof(config->gw_address))) 
        {
            debug(LOG_ERR, "Could not get IP of gw interface %s, exiting...", config->gw_interface);
            rhy_exit(1);
        }
        debug(LOG_DEBUG, "%s = %s", config->gw_interface, config->gw_address);
    }
    
    /* If we don't have the Gateway ID, construct it from the internal MAC address.
     * "Can't fail" so exit() if the impossible happens. */
    if (IS_NULL_CONFIG(gw_id))
    {
        debug(LOG_DEBUG, "Finding MAC of gw interface %s", config->gw_interface);
        if (!get_iface_mac2(config->gw_interface, config->gw_id, sizeof(config->gw_id)))
        {
            debug(LOG_ERR, "Could not get MAC of gw interface %s, exiting...", config->gw_interface);
            rhy_exit(1);
        }
        debug(LOG_DEBUG, "%s = %s", config->gw_interface, config->gw_id);
    }
    
    /* Initializes the web server */
    debug(LOG_NOTICE, "Creating InternerHttp web server http listenner on interface %s, %s:%d", 
                       config->gw_interface, config->gw_address, config->gw_port);
    webserver = httpdCreate(config->gw_address, config->gw_port, "InternerHttp");
    if(NULL == webserver)
    {
        debug(LOG_ERR, "Could not create InternerHttp web server: %s", strerror(errno));
        rhy_exit(1);
    }
    
#if NEED_SSL_WEB_SERVICE
    /* Initializes the web server */
    debug(LOG_NOTICE, "Creating InternerHttps web server https listenner on interface %s, %s:%d", 
                       config->gw_interface, config->gw_address, 443);
    webserverhttps = httpdCreate(config->gw_address, 443, "InternerHttps");
    if(NULL == webserverhttps)
    {
        debug(LOG_ERR, "Could not create InternerHttps server: %s", strerror(errno));
        rhy_exit(1);
    }
#endif
    
    if(webserver)
    {
        char FilePath[MAX_GENERAL_LEN]={0};
        snprintf(FilePath, sizeof(FilePath)-1, "/%s", config->company);
        register_fd_cleanup_on_fork(webserver->serverSock);
        httpdSetErrorFunction(webserver, 404, http_callback_404);
        httpdAddCContent(webserver, "/", config->company, 0, NULL, http_callback_wifidog);
        httpdAddCContent(webserver, FilePath, "", 0, NULL, http_callback_wifidog);
        httpdAddCContent(webserver, FilePath, "about", 0, NULL, http_callback_about);
        httpdAddCContent(webserver, FilePath, "status", 0, NULL, http_callback_status);
        httpdAddCContent(webserver, FilePath, "statistics", 0, NULL, http_callback_statistics);
        //httpdAddCContent(webserver, FilePath, "auth", 0, NULL, http_callback_auth);
        //httpdAddCContent(webserver, FilePath, "disconnect", 0, NULL, http_callback_disconnect);
        //httpdAddCContent(webserver, "/", "sms", 0, NULL, http_callback_smsquest);
        //httpdAddCContent(webserver, "/", "login", 0, NULL, http_callback_checklogin);
        httpdAddCContent(webserver, "/", DEFAULT_PORTAL_FILENAME, 0, NULL, http_send_portal_page);
        httpdAddCContent(webserver, "/", DEFAULT_FAVICONICO_FILENAME, 0, NULL, http_send_favicon_ico);
        for (auth_server = get_auth_server(); auth_server != NULL; auth_server = auth_server->next) 
        {
            httpdAddCContent(webserver, auth_server->passive_path, auth_server->authserv_sms_script_path_fragment, 
                                        0, NULL, http_callback_smsquest);
            httpdAddCContent(webserver, auth_server->passive_path, auth_server->authserv_login_script_path_fragment, 
                                        0, NULL, http_callback_checklogin);
        }
        httpdSetWebAccessLog(webserver, config->portal_save_path);
        httpdSetWebErrorLog(webserver, config->portal_save_path);
        httpdDumpContent(webserver);
    }
    
    if(webserverhttps)
    {
        register_fd_cleanup_on_fork(webserverhttps->serverSock);
        httpdSetErrorFunction(webserverhttps, 404, http_callback_404);
        httpdSetWebAccessLog(webserverhttps, config->portal_save_path);
        httpdSetWebErrorLog(webserverhttps, config->portal_save_path);
        httpdDumpContent(webserverhttps);
    }
    
    if(extwebserver)
    {
        register_fd_cleanup_on_fork(extwebserver->serverSock);
        httpdAddCContent(extwebserver, "/", "pass", 0, NULL, http_callback_pass);
        httpdAddCContent(extwebserver, "/", "off", 0, NULL, http_callback_offline);
        for (auth_server = get_auth_server(); auth_server != NULL; auth_server = auth_server->next) 
        {
            httpdAddCContent(extwebserver, auth_server->passive_path, auth_server->authserv_pass_script_path_fragment, 
                                        0, NULL, http_callback_pass);
            httpdAddCContent(extwebserver, auth_server->passive_path, auth_server->authserv_offline_script_path_fragment, 
                                        0, NULL, http_callback_offline);
        }
        httpdSetWebAccessLog(extwebserver, config->portal_save_path);
        httpdSetWebErrorLog(extwebserver, config->portal_save_path);
        httpdDumpContent(extwebserver);
    }
    
    /* Reset the firewall (if process crashed) */
    debug(LOG_INFO, "Reset and initialize the firewall");
    fw_destroy();
    /* Then initialize it */
    if (!fw_init()) {
        debug(LOG_ERR, "FATAL: Failed to initialize firewall");
        rhy_exit(1);
    }
    
    /* Start clean up thread */
    debug(LOG_INFO, "pthread_create thread_client_timeout_check");
    result = pthread_create(&tid_client_timedout, NULL, (void *)thread_client_timeout_check, NULL);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to pthread_create(thread_client_timeout_check) -exiting");
        termination_handler(0);
    }
    pthread_detach(tid_client_timedout);

    /*************add for router reset*******************/
    debug(LOG_INFO, "add router reset register");
    registerPacketHandler(E_TYPE_RESET_OS, router_reset);

    /*************add for version update*******************/
    debug(LOG_INFO, "pthread_create thread_version_update");
    registerPacketHandler(E_TYPE_REMOTE_UPGRADE, version_update_start);
    result = pthread_create(&tid_version_update, NULL, (void *)thread_version_update, NULL);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to pthread_create(thread_version_update) -exiting");
        termination_handler(0);
    }
    pthread_detach(tid_version_update);

    registerPacketHandler(E_TYPE_DEVICE_REGISTER, tcp_callback_register_resp);
    registerPacketHandler(E_TYPE_DEVICE_HB_ECHO, tcp_callback_echo);
    registerPacketHandler(E_TYPE_REMOTE_LOGIN, tcp_callback_pass);
    /* Start heartbeat thread */
    debug(LOG_INFO, "pthread_create thread_comm_agent");
    result = pthread_create(&tid_comm_agent, NULL, (void *)thread_comm_agent, NULL);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to pthread_create(thread_comm_agent) -exiting");
        termination_handler(0);
    }
    pthread_detach(tid_comm_agent);

    /* Start portal update thread */
    debug(LOG_INFO, "pthread_create thread_portal_updates");
    result = pthread_create(&tid_portal_update, NULL, (void *)thread_portal_update, NULL);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to pthread_create(thread_portal_update) -exiting");
        termination_handler(0);
    }
    pthread_detach(tid_portal_update);

    if(webserver)
    {
        debug(LOG_INFO, "pthread_create thread_listen_web_connect on internal web server http listenner");
        result = pthread_create(&tid_webserver_http_listenner, NULL, (void *)thread_listen_web_connect, webserver);
        if (result != 0) {
            debug(LOG_ERR, "FATAL: Failed to pthread_create(thread_listen_web_connect) on internal web server http listenner - exiting");
            termination_handler(0);
        }
        pthread_detach(tid_webserver_http_listenner);
    }
    
    if(webserverhttps)
    {
        debug(LOG_INFO, "pthread_create on internal web server https listenner");
        result = pthread_create(&tid_webserver_https_listenner, NULL, (void *)thread_listen_web_connect, webserverhttps);
        if (result != 0) {
            debug(LOG_ERR, "FATAL: Failed to pthread_create(thread_listen_web_connect) on internal web server https listenner - exiting");
            termination_handler(0);
        }
        pthread_detach(tid_webserver_https_listenner);
    }
    
    if(extwebserver)
    {
        debug(LOG_INFO, "pthread_create on external web server http listenner");
        result = pthread_create(&tid_extwebserver_listenner, NULL, (void *)thread_listen_web_connect, extwebserver);
        if (result != 0) {
            debug(LOG_ERR, "FATAL: Failed to pthread_create(thread_listen_web_connect) on external web server http listenner -exiting");
            termination_handler(0);
        }
        pthread_detach(tid_webserver_http_listenner);
    }

    debug(LOG_INFO, "pthread_create thread_comm_dpi");
    get_ext_iface_name(&gtDpiParam.portName, MAX_INTERFACE_NAME_LEN);
    strncpy(&gtDpiParam.bpfFilter, config_get_config()->dpi_bpf, sizeof(gtDpiParam.bpfFilter)-1);
    strncpy(&gtDpiParam.logPath, config_get_config()->dpi_log_file, sizeof(gtDpiParam.logPath)-1);
    gtDpiParam.dpiFlag = config_get_config()->dpi_flag;
    debug(LOG_DEBUG, "dpi flag: %d, parameters:%s, %s, %s", gtDpiParam.logFlag, gtDpiParam.portName, gtDpiParam.bpfFilter, gtDpiParam.logPath);
    result = pthread_create(&tid_dpi_main, NULL, (void *)thread_comm_dpi, &gtDpiParam);
    if (result != 0) {
    	debug(LOG_ERR, "FATAL: Failed to pthread_create(thread_comm_dpi) -exiting");
    	termination_handler(0);
    }
    pthread_detach(tid_dpi_main);

#if 1
    /* Start control thread */
    debug(LOG_INFO, "MainThread[%lu] start running as thread_wdctl", pthread_self());
    thread_wdctl((void *)(config->wdctl_sock));
#else
    /* Start control thread */
    debug(LOG_INFO, "pthread_create thread_wdctl");
    result = pthread_create(&tid, NULL, (void *)thread_wdctl, (void *)safe_strdup(config->wdctl_sock));
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to pthread_create(thread_wdctl) -exiting");
        termination_handler(0);
    }
    pthread_detach(tid);

    tval.tv_sec=SECONDS_ONE_DAY;
    tval.tv_usec=0;
    while(1)
    {
        debug(LOG_DEBUG, "MainThread[%lu] goes into dead sleep...", pthread_self());
        result = select(0,NULL,NULL,NULL,&tval);
        debug(LOG_DEBUG, "MainThread[%lu] wakeup with ret:%d", result, pthread_self());
    }
#endif
    /* never reached */
}

/** Reads the configuration file and then starts the main loop */
int gw_main(int argc, char** argv)
{
    /* Init the signals to catch chld/quit/etc */
    init_signals();

    T_CONFIG *config = config_get_config();
    config_init();

    parse_commandline(argc, argv);

    /* Initialize the config */
    config_read(config->configfile);
    config_validate();

    setExcpInfoSaveFile(config->portal_save_path, DEFAULT_EXCPINFO_FILENAME);
    
    /* Initializes the linked list of connected clients */
    client_list_init(config->max_client_num);

    if (restart_orig_pid) {
        /*
         * We were restarted and our parent is waiting for us to talk to it over the socket
         */
        get_clients_from_parent();

        /*
         * At this point the parent will start destroying itself and the firewall. Let it finish it's job before we continue
         */
        while (kill(restart_orig_pid, 0) != -1) {
            debug(LOG_INFO, "Waiting for parent PID %d to die before continuing loading", restart_orig_pid);
            sleep(1);
        }

        debug(LOG_INFO, "Parent PID %d seems to be dead. Continuing loading.", restart_orig_pid);
    }

    if (config->daemon) {

        debug(LOG_INFO, "Forking into background");

        switch (safe_fork()) {
        case 0:                /* child */
            setsid();
            append_x_restartargv();
            main_loop();
            break;

        default:               /* parent */
            exit(0);
            break;
        }
    } else {
        append_x_restartargv();
        main_loop();
    }

    return (0);                 /* never reached */
}


