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
/** @file common.h
    @brief Common constants and other bits
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _COMMON_H_
#define _COMMON_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <pthread.h>
#include <limits.h>

#ifndef typeof
#define typeof __typeof__
#endif

#ifndef asm
#define asm __asm__
#endif

/******* Macro to mark functions and fields scheduled for removal *****/
#define _RHY_DEPRECATED	__attribute__((__deprecated__))

/*********** Macros to eliminate unused variable warnings ********/

/****** short definition to mark a function parameter unused *****/
#define _RHY_UNUSED __attribute__((__unused__))

/****** Force a structure to be packed *****/
#define _RHY_PACKED __attribute__ ((__packed__))

/****** Force alignment ******/
#define _RHY_ALIGNED(a) __attribute__((__aligned__(a)))

#define RHY_SIZEOF(STRUCT, MEMBER) (sizeof(((STRUCT *)0)->MEMBER))

#define RHY_OFFSETOF(STRUCT, MEMBER) (size_t)&(((STRUCT *)0)->MEMBER)

#define MAX_BUF                   4096

#define MAX_TEMP_BUFFER_SIZE      256

#define MAX_PATH_LEN              256

#define PORTAL_VERSTRING_LEN      128

#define MAX_IP_ADDR_LEN           16

#define MAX_MAC_ADDR_LEN          18

#define MAX_PHONE_LEN             12

#define MAX_RECORD_ID_LEN         20

#define MAX_TOKEN_LEN             10

#define MAX_USER_TYPE_LEN         10

#define MAX_INTERFACE_NAME_LEN    50

#define MAX_GENERAL_LEN           100

#define MAX_SELECT_SECONDS        10

#define DAEMON_SELECT_SECONDS     30

#define SECONDS_ONE_DAY          (60*60*24)

#define ANY_IP_ADDR_STRING        "0.0.0.0"

#define ZERO_STR_AS_PLACE_CODE    "000000000000"

#define MAX_AUTH_NAME_LEN         10

#define MINIMUM_STARTED_TIME      1041379200

#define TCP_KEEPALIVE_INTERVAL    100

#define CONFIG_SET(key, value) do{ \
    T_CONFIG *pConf = config_get_config(); \
    memset(pConf->key, 0, sizeof(pConf->key)); \
    strncpy(pConf->key, value, sizeof(pConf->key)-1); \
}while(0)

#define CONFIG_CLEAR_STRING(key) do{ \
    T_CONFIG *pConf = config_get_config(); \
    memset(pConf->key, 0, sizeof(pConf->key)); \
}while(0)

#define IS_NULL_CONFIG(key) (0==(config_get_config()->key[0]))

#ifndef max
#define max(a, b) (a > b) ? (a) : (b)
#endif

#ifndef min
#define min(a, b) (a < b) ? (a) : (b)
#endif

#ifndef FALSE
#define FALSE false
#endif

#ifndef TRUE
#define TRUE true
#endif

typedef enum _ServiceType{
    E_TYPE_MIN             = 0,
    E_TYPE_DEVICE_REGISTER = 1,
    E_TYPE_DEVICE_SIGNATURE   ,     //verify signature, reserved for future use
    E_TYPE_REMOTE_LOGIN    = 3,
    E_TYPE_REMOTE_UPGRADE  = 4,
    E_TYPE_DEVICE_HB_ECHO  = 5,     //heartbeat echo
    E_TYPE_RESET_OS        = 6,     //reset openwrt system
    E_TYPE_RESET_PROC,      //only reset the process its self, not used now
    E_TYPE_REMOTE_LOGOUT,   //not used now
    E_TYPE_GET_STATUS,      //fetch operation stauts infomation, not used now
    E_TYPE_GET_STATISTICS,  //fetch operation statistics infomation, not used now
    E_TYPE_SET_LOGLVL,      //set log level 0-8
    E_TYPE_MAX
}E_SERVICE_TYPE;

#define MAX_TCPREQ_VAR_NUM             20
#define MAX_TCPREQ_VAR_LEN             20
typedef struct _tcp_var {
    char name[MAX_TCPREQ_VAR_LEN];
    char value[MAX_TCPREQ_VAR_LEN];
} tcpVar;

typedef struct _ServicePacketHdr {
    char distinguisher[4];
    unsigned int xid;
    char type;
    unsigned int length;
}_RHY_PACKED T_SERVICEPACKETHDR;

typedef struct {
    int sock;
    T_SERVICEPACKETHDR head;
    tcpVar variables[MAX_TCPREQ_VAR_NUM];
    int    varCount;
    T_SERVICEPACKETHDR resphead;
    char   respValue[MAX_BUF];
    int    respLen;
}_RHY_PACKED tcp_request;

typedef bool (* pfSvcTypeCallBack)(char* msgData, unsigned int msgLen, tcp_request* r);
bool registerPacketHandler(E_SERVICE_TYPE type, pfSvcTypeCallBack callBack);
tcpVar* tcpGetVariableByName(tcp_request* r, const char* name);
void tcpSetResponseHead(tcp_request* r, T_SERVICEPACKETHDR* head);
void tcpSetResponseData(tcp_request* r, char* data, int len);
int tcpOutputResponse(tcp_request* r);

#endif /* _COMMON_H_ */
