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
  @file util.c
  @brief Misc utility functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2006 Benoit Grégoire <bock@step.polymtl.ca>
 */

#include "common.h"

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <netdb.h>
#include <fcntl.h>

#include "safe.h"
#include "util.h"
#include "debug.h"
#include "pstring.h"

#include "../config.h"

#define LOCK_GHBN() do { \
	debug(LOG_DEBUG, "Locking wd_gethostbyname()"); \
	pthread_mutex_lock(&ghbn_mutex); \
	debug(LOG_DEBUG, "wd_gethostbyname() locked"); \
} while (0)

#define UNLOCK_GHBN() do { \
	debug(LOG_DEBUG, "Unlocking wd_gethostbyname()"); \
	pthread_mutex_unlock(&ghbn_mutex); \
	debug(LOG_DEBUG, "wd_gethostbyname() unlocked"); \
} while (0)

#include "../config.h"
#ifdef __ANDROID__
#define WD_SHELL_PATH "/system/bin/sh"
#else
#define WD_SHELL_PATH "/bin/sh"
#endif

/** @brief FD for icmp raw socket */
static int icmp_fd;

/** @brief Mutex to protect gethostbyname since not reentrant */
static pthread_mutex_t ghbn_mutex = PTHREAD_MUTEX_INITIALIZER;

/** Fork a child and execute a shell command, the parent
 * process waits for the child to return and returns the child's exit()
 * value.
 * @return Return code of the command
 */
int execute(const char *cmd_line, int quiet)
{
    int pid, status, rc;

    const char *new_argv[4];
    new_argv[0] = WD_SHELL_PATH;
    new_argv[1] = "-c";
    new_argv[2] = cmd_line;
    new_argv[3] = NULL;

    pid = safe_fork();
    if (pid == 0) {             /* for the child process:         */
        /* We don't want to see any errors if quiet flag is on */
        if (quiet)
            close(2);
        if (execvp(WD_SHELL_PATH, (char *const *)new_argv) == -1) { /* execute the command  */
            debug(LOG_ERR, "execvp(): %s", strerror(errno));
        } else {
            debug(LOG_ERR, "execvp() failed");
        }
        exit(1);
    }

    /* for the parent:      */
    debug(LOG_TRACE, "Waiting for PID %d to exit", pid);
    rc = waitpid(pid, &status, 0);
    debug(LOG_TRACE, "Process PID %d exited", rc);
    
    if (-1 == rc) {
        debug(LOG_ERR, "waitpid() failed (%s)", strerror(errno));
        return 1; /* waitpid failed. */
    }

    if (WIFEXITED(status)) {
        return (WEXITSTATUS(status));
    } else {
        /* If we get here, child did not exit cleanly. Will return non-zero exit code to caller*/
        debug(LOG_DEBUG, "Child may have been killed.");
        return 1;
    }
}

struct in_addr *wd_gethostbyname(const char *name)
{
    struct hostent *he = NULL;
    struct in_addr *addr = NULL;
    struct in_addr *in_addr_temp = NULL;

    /* XXX Calling function is reponsible for free() */

    addr = safe_malloc(sizeof(*addr));

    LOCK_GHBN();

    he = gethostbyname(name);

    if (he == NULL) {
        UNLOCK_GHBN();
        free(addr);
        return NULL;
    }

    in_addr_temp = (struct in_addr *)he->h_addr_list[0];
    addr->s_addr = in_addr_temp->s_addr;

    UNLOCK_GHBN();

    return addr;
}

struct in_addr *wd_gethostbyipstring(const char *ip)
{
    struct in_addr *addr = NULL;
    int ret;
    
    addr = safe_malloc(sizeof(*addr));
    
    ret = inet_aton(ip, addr);
    
    if(ret == 0)
    {
        free(addr);
        return NULL;
    }

    return addr;
}

/* convert mac address format aabbccddeeff to aa:bb:cc:dd:ee:ff */
char* wd_convertmac(const char* mac)
{
    char* colonMac = NULL;
    int i=0;
    int j=0;
    
    /* Maximuly 18 characters in such kind of mac string format, aa:bb:cc:dd:ee:ff */
    colonMac = safe_malloc(MAX_MAC_ADDR_LEN);
    while(i<MAX_MAC_ADDR_LEN-1 && mac[i])
    {
        if(':'!=mac[i])
        {
            colonMac[j]=mac[i];
            j++;
        }
        i++;
    }
    return colonMac;
}

char* get_iface_ip(const char* ifName)
{
    struct ifreq if_data;
    struct in_addr in;
    char *ip_str;
    int sockd;
    u_int32_t ip;

    /* Create a socket */
    if ((sockd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        debug(LOG_ERR, "socket(): %s", strerror(errno));
        return NULL;
    }

    /* Get IP of internal interface */
    strncpy(if_data.ifr_name, ifName, 15);
    if_data.ifr_name[15] = '\0';

    /* Get the IP address */
    if (ioctl(sockd, SIOCGIFADDR, &if_data) < 0) {
        debug(LOG_ERR, "ioctl(): SIOCGIFADDR %s", strerror(errno));
        close(sockd);
        return NULL;
    }
    memcpy((void *)&ip, (void *)&if_data.ifr_addr.sa_data + 2, 4);
    in.s_addr = ip;

    ip_str = inet_ntoa(in);
    close(sockd);
    return safe_strdup(ip_str);
}

bool get_iface_ip2(const char* ifName, char* ipStr, int bufLen)
{
    struct ifreq if_data;
    struct in_addr in;
    int sockd;
    u_int32_t ip;

    /* Create a socket */
    if ((sockd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        debug(LOG_ERR, "socket(): %s", strerror(errno));
        return FALSE;
    }

    /* Get IP of internal interface */
    strncpy(if_data.ifr_name, ifName, 15);
    if_data.ifr_name[15] = '\0';

    /* Get the IP address */
    if (ioctl(sockd, SIOCGIFADDR, &if_data) < 0) {
        debug(LOG_ERR, "ioctl(): SIOCGIFADDR %s", strerror(errno));
        close(sockd);
        return FALSE;
    }
    memcpy((void *)&ip, (void *)&if_data.ifr_addr.sa_data + 2, 4);
    in.s_addr = ip;

    memset(ipStr, 0, bufLen);
    strncpy(ipStr, inet_ntoa(in), bufLen-1);
    close(sockd);
    return TRUE;
}

char* get_iface_mac(const char *ifName)
{
    int r, s;
    struct ifreq ifr;
    char* hwaddr;
    char mac[13]={0};

    strncpy(ifr.ifr_name, ifName, 15);
    ifr.ifr_name[15] = '\0';

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == s) {
        debug(LOG_ERR, "get_iface_mac socket: %s", strerror(errno));
        return NULL;
    }

    r = ioctl(s, SIOCGIFHWADDR, &ifr);
    if (r == -1) {
        debug(LOG_ERR, "get_iface_mac ioctl(SIOCGIFHWADDR): %s", strerror(errno));
        close(s);
        return NULL;
    }

    hwaddr = ifr.ifr_hwaddr.sa_data;
    close(s);
    snprintf(mac, sizeof(mac)-1, "%02X%02X%02X%02X%02X%02X",
             hwaddr[0] & 0xFF,
             hwaddr[1] & 0xFF, hwaddr[2] & 0xFF, hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);

    return safe_strdup(mac);
}

bool get_iface_mac2(const char *ifName, char* macStr, int bufLen)
{
    int r, s;
    struct ifreq ifr;
    char* hwaddr;

    strncpy(ifr.ifr_name, ifName, 15);
    ifr.ifr_name[15] = '\0';

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == s) {
        debug(LOG_ERR, "get_iface_mac socket: %s", strerror(errno));
        return FALSE;
    }

    r = ioctl(s, SIOCGIFHWADDR, &ifr);
    if (r == -1) {
        debug(LOG_ERR, "get_iface_mac ioctl(SIOCGIFHWADDR): %s", strerror(errno));
        close(s);
        return FALSE;
    }

    hwaddr = ifr.ifr_hwaddr.sa_data;
    close(s);
    memset(macStr, 0, bufLen);
    snprintf(macStr, bufLen-1, "%02X%02X%02X%02X%02X%02X",
             hwaddr[0] & 0xFF,
             hwaddr[1] & 0xFF, hwaddr[2] & 0xFF, hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);
    return TRUE;
}

bool get_ext_iface_ip(char* extIpaddrBuf, int bufLen)
{
    char ext_interface[MAX_INTERFACE_NAME_LEN]={0};

    //LOCK_CONFIG();
    get_ext_iface_name(ext_interface, MAX_INTERFACE_NAME_LEN);

    if(0==ext_interface[0])
    {
        //UNLOCK_CONFIG();
        debug(LOG_ERR, "get_ext_iface_ip fatal error: no external interface");
        return FALSE;
    }
    //UNLOCK_CONFIG();
    
    return get_iface_ip2(ext_interface, extIpaddrBuf, bufLen);
}

bool get_ext_iface_mac(char* extMacBuf, int bufLen)
{
    char ext_interface[MAX_INTERFACE_NAME_LEN]={0};

    //LOCK_CONFIG();
    get_ext_iface_name(ext_interface, MAX_INTERFACE_NAME_LEN);

    if(0==ext_interface[0])
    {
        //UNLOCK_CONFIG();
        debug(LOG_ERR, "get_ext_iface_mac fatal error: no external interface");
        return FALSE;
    }
    //UNLOCK_CONFIG();
    
    return get_iface_mac2(ext_interface, extMacBuf, bufLen);
}

bool get_ext_iface_name(char* extPortBuf, int bufLen)
{
    const T_CONFIG *config = config_get_config();
    if (!IS_NULL_CONFIG(external_interface)) 
    {
        strncpy(extPortBuf, config->external_interface, bufLen-1);
        return TRUE;
    }
    else
    {
        return get_ext_iface(extPortBuf, sizeof(bufLen));
    }
}

bool get_ext_iface(char* ifBuf, int bufLen)
{
    FILE* input;
    int i = 1;
    int keep_detecting = 1;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;
    char device[MAX_INTERFACE_NAME_LEN]={0};
    char gw[MAX_IP_ADDR_LEN]={0};
    
    debug(LOG_DEBUG, "get_ext_iface(): Autodectecting the external interface from routing table");
    memset(ifBuf, 0, bufLen);
    
    while (keep_detecting) {
        input = fopen("/proc/net/route", "r");
        if (NULL == input) {
            debug(LOG_ERR, "Could not open /proc/net/route (%s).", strerror(errno));
            return FALSE;
        }
        while (!feof(input)) {
            /* XXX scanf(3) is unsafe, risks overrun */
            if ((fscanf(input, "%15s %15s %*s %*s %*s %*s %*s %*s %*s %*s %*s\n", device, gw) == 2)
                && strcmp(gw, "00000000") == 0) {
                debug(LOG_INFO, "get_ext_iface(): Detected %s as the default interface after trying %d", device, i);
                fclose(input);
                strncpy(ifBuf, device, bufLen-1);
                return TRUE;
            }
        }
        fclose(input);
        debug(LOG_ERR,
              "get_ext_iface(): Failed to detect the external interface after try %d (maybe the interface is not up yet?).  Retry limit: %d",
              i, NUM_EXT_INTERFACE_DETECT_RETRY);
        /* Sleep for EXT_INTERFACE_DETECT_RETRY_INTERVAL seconds */
        timeout.tv_sec = time(NULL) + EXT_INTERFACE_DETECT_RETRY_INTERVAL;
        timeout.tv_nsec = 0;
        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);
        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);   /* XXX need to possibly add this thread to termination_handler */
        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);
        //for (i=1; i<=NUM_EXT_INTERFACE_DETECT_RETRY; i++) {
        if (NUM_EXT_INTERFACE_DETECT_RETRY != 0 && i > NUM_EXT_INTERFACE_DETECT_RETRY) {
            keep_detecting = 0;
        }
        i++;
    }
    debug(LOG_ERR, "get_ext_iface(): Failed to detect the external interface after %d tries, aborting", i);
    return FALSE;
}

/** Initialize the ICMP socket
 * @return A boolean of the success
 */
int init_icmp_socket(void)
{
    int flags, oneopt = 1, zeroopt = 0;

    debug(LOG_INFO, "Creating ICMP socket");
    if ((icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1 ||
        (flags = fcntl(icmp_fd, F_GETFL, 0)) == -1 ||
        fcntl(icmp_fd, F_SETFL, flags | O_NONBLOCK) == -1 ||
        setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &oneopt, sizeof(oneopt)) ||
        setsockopt(icmp_fd, SOL_SOCKET, SO_DONTROUTE, &zeroopt, sizeof(zeroopt)) == -1) {
        debug(LOG_ERR, "Cannot create ICMP raw socket.");
        return 0;
    }
    return 1;
}

/** Close the ICMP socket. */
void close_icmp_socket(void)
{
    debug(LOG_INFO, "Closing ICMP socket");
    close(icmp_fd);
}

/**
 * Ping an IP.
 * @param IP/host as string, will be sent to gethostbyname
 */
void icmp_ping(const char *host)
{
    struct sockaddr_in saddr;
    struct {
        struct ip ip;
        struct icmp icmp;
    } packet;
    unsigned int i, j;
    int opt = 2000;
    unsigned short id = rand16();

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    inet_aton(host, &saddr.sin_addr);
#if defined(HAVE_SOCKADDR_SA_LEN)
    saddr.sin_len = sizeof(struct sockaddr_in);
#endif

    memset(&packet.icmp, 0, sizeof(packet.icmp));
    packet.icmp.icmp_type = ICMP_ECHO;
    packet.icmp.icmp_id = id;

    for (j = 0, i = 0; i < sizeof(struct icmp) / 2; i++)
        j += ((unsigned short *)&packet.icmp)[i];

    while (j >> 16)
        j = (j & 0xffff) + (j >> 16);

    packet.icmp.icmp_cksum = (j == 0xffff) ? j : ~j;

    if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
        debug(LOG_ERR, "setsockopt(): %s", strerror(errno));

    if (sendto(icmp_fd, (char *)&packet.icmp, sizeof(struct icmp), 0,
               (const struct sockaddr *)&saddr, sizeof(saddr)) == -1)
        debug(LOG_ERR, "sendto(): %s", strerror(errno));

    opt = 1;
    if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
        debug(LOG_ERR, "setsockopt(): %s", strerror(errno));

    return;
}

/** Get a 16-bit unsigned random number.
 * @return unsigned short a random number
 */
unsigned short rand16(void)
{
    static int been_seeded = 0;

    if (!been_seeded) {
        unsigned int seed = 0;
        struct timeval now;

        /* not a very good seed but what the heck, it needs to be quickly acquired */
        gettimeofday(&now, NULL);
        seed = now.tv_sec ^ now.tv_usec ^ (getpid() << 16);

        srand(seed);
        been_seeded = 1;
    }

    /* Some rand() implementations have less randomness in low bits
     * than in high bits, so we only pay attention to the high ones.
     * But most implementations don't touch the high bit, so we
     * ignore that one. */
    return ((unsigned short)(rand() >> 15));
}

unsigned long long get_millisecond()
{
    struct timeval now;
    unsigned long long millisec=0;
    gettimeofday(&now, NULL);
    millisec = now.tv_sec;
    millisec = millisec*1000+(unsigned long long)(now.tv_usec/1000);
    return millisec;
}
/*
 * Save pid of this process in pid file
 * @param 'pf' as string, it is the pid file absolutely path
 */
void save_pid_file(const char *pf)
{
    if (pf) {
        FILE *f = fopen(pf, "w");
        if (f) {
            fprintf(f, "%d\n", getpid());

            int ret = fclose(f);
            if (ret == EOF) /* check the return value of fclose */
                debug(LOG_ERR, "fclose() on file %s was failed (%s)", pf, strerror(errno));
        } else /* fopen return NULL, open file failed */
            debug(LOG_ERR, "fopen() on flie %s was failed (%s)", pf, strerror(errno));
    }

    return;
}

