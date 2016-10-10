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

/* $Id$ */
/** @file fw_iptables.h
    @brief Firewall iptables functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _FW_IPTABLES_H_
#define _FW_IPTABLES_H_

#include "firewall.h"
//#define CHAIN_NAME_WITH_GWID 1

/*@{*/
/**Iptable chain names used by process */
#ifdef CHAIN_NAME_WITH_GWID
#define CHAIN_OUTGOING       "SelfDef_$ID$_Outgoing"
#define CHAIN_TO_INTERNET    "SelfDef_$ID$_Internet"
#define CHAIN_TO_ROUTER      "SelfDef_$ID$_Router"
#define CHAIN_INCOMING       "SelfDef_$ID$_Incoming"
#define CHAIN_AUTHSERVERS    "SelfDef_$ID$_AuthServers"
#define CHAIN_GLOBAL         "SelfDef_$ID$_Global"
#define CHAIN_VALIDATE       "SelfDef_$ID$_Validate"
#define CHAIN_KNOWN          "SelfDef_$ID$_Known"
#define CHAIN_UNKNOWN        "SelfDef_$ID$_Unknown"
#define CHAIN_LOCKED         "SelfDef_$ID$_Locked"
#define CHAIN_TRUSTED        "SelfDef_$ID$_Trusted"
#define CHAIN_AUTH_IS_DOWN   "SelfDef_$ID$_AuthIsDown"
#else
#define CHAIN_OUTGOING       "RHY_Outgoing"
#define CHAIN_TO_INTERNET    "RHY_Internet"
#define CHAIN_TO_ROUTER      "RHY_Router"
#define CHAIN_INCOMING       "RHY_Incoming"
#define CHAIN_AUTHSERVERS    "RHY_AuthServers"
#define CHAIN_GLOBAL         "RHY_Global"
#define CHAIN_VALIDATE       "RHY_Validate"
#define CHAIN_KNOWN          "RHY_Known"
#define CHAIN_UNKNOWN        "RHY_Unknown"
#define CHAIN_LOCKED         "RHY_Locked"
#define CHAIN_TRUSTED        "RHY_Trusted"
#define CHAIN_AUTH_IS_DOWN   "RHY_AuthIsDown"
#endif
/* build-in tables */
#define TABLE_FILTER         "filter"
#define TABLE_NAT            "nat"
#define TABLE_MANGLE         "mangle"

/*@}*/

/** Used by iptables_fw_access to select if the client should be granted of denied access */
typedef enum fw_access_t_ {
    FW_ACCESS_ALLOW,
    FW_ACCESS_DENY,
    FW_ACCESS_REPLACE
} fw_access_t;

/** @brief Initialize the firewall */
int iptables_fw_init(void);

/** @brief Initializes the authservers table */
void iptables_fw_set_authservers(void);

/** @brief Clears the authservers table */
void iptables_fw_clear_authservers(void);

/** @brief Destroy the firewall */
int iptables_fw_destroy(void);

/** @brief Helper function for iptables_fw_destroy */
int iptables_fw_destroy_mention(const char *table, const char *chain, const char *mention);

/** @brief Define the access of a specific client */
bool iptables_fw_access(fw_access_t type, const char *ip, const char *mac, int tag);

/** @brief Define the access of a host */
int iptables_fw_access_host(fw_access_t type, const char *host);

/** @brief Set a mark when auth server is not reachable */
int iptables_fw_auth_unreachable(int tag);

/** @brief Remove mark when auth server is reachable again */
int iptables_fw_auth_reachable(void);

/** @brief All counters in the client list */
int iptables_fw_counters_update(void);

#endif                          /* _IPTABLES_H_ */
