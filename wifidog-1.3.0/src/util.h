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

/** @file util.h
    @brief Misc utility functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _UTIL_H_
#define _UTIL_H_

/** How many times should we try detecting the interface with the default route
 * (in seconds).  If set to 0, it will keep retrying forever */
#define NUM_EXT_INTERFACE_DETECT_RETRY 0
/** How often should we try to detect the interface with the default route
 *  if it isn't up yet (interval in seconds) */
#define EXT_INTERFACE_DETECT_RETRY_INTERVAL 1

/** @brief Execute a shell command */
int execute(const char *, int);

/** @brief Thread safe gethostbyname */
struct in_addr *wd_gethostbyname(const char *);

/** @brief Thread safe gethostbyname */
struct in_addr *wd_gethostbyipstring(const char *ip);

/** @brief convert mac address format aabbccddeeff to aa:bb:cc:dd:ee:ff */
char* wd_convertmac(const char* mac);

/** @brief Get IP address of an interface */
char* get_iface_ip(const char*);
bool get_iface_ip2(const char*, char*, int);

/** @brief Get MAC address of an interface */
char *get_iface_mac(const char*);
bool get_iface_mac2(const char*, char*, int);

/** @brief Get interface name of default gateway */
bool get_ext_iface(char*, int);

/** @brief Get external interface ip */
bool get_ext_iface_ip(char*, int);

bool get_ext_iface_mac(char*, int);

/** @brief Initialize the ICMP socket */
int init_icmp_socket(void);

/** @brief Close the ICMP socket. */
void close_icmp_socket(void);

/** @brief ICMP Ping an IP */
void icmp_ping(const char *);

/** @brief get random number */
unsigned short rand16(void);

/** @brief get time in millisecond unit */
unsigned long long get_millisecond();

/** @brief Save pid of this process in pid file */
void save_pid_file(const char *);

#endif                          /* _UTIL_H_ */
