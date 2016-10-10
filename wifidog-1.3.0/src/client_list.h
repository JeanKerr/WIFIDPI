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
/** @file client_list.h
    @brief Client List functions
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#ifndef _CLIENT_LIST_H_
#define _CLIENT_LIST_H_

#define USE_NEW_LOCK
/** Global mutex to protect access to the client list */
extern pthread_mutex_t client_list_mutex;
extern pthread_mutex_t client_pool_mutex;

/** Counters struct for a client's bandwidth usage (in bytes)
 */
typedef struct _t_counters {
    unsigned long long inComingByt;          /**< @brief Incoming data total(bytes) */
    unsigned long long outGoingByt;          /**< @brief Outgoing data total(bytes) */
    unsigned long long inComingPkt;          /**< @brief Incoming data total(packets) */
    unsigned long long outGoingPkt;          /**< @brief Outgoing data total(packets) */
    unsigned long long inComingBytHistory;   /**< @brief Incoming data(bytes) before process restarted*/
    unsigned long long outGoingBytHistory;   /**< @brief Outgoing data(bytes) before process restarted*/
    unsigned long long inComingPktHistory;   /**< @brief Incoming data(packets) before process restarted*/
    unsigned long long outGoingPktHistory;   /**< @brief Outgoing data(packets) before process restarted*/
    unsigned long long inComingBytDelta;     /**< @brief Incoming data(bytes) after last report*/
    unsigned long long outGoingBytDelta;     /**< @brief Outgoing data(bytes) after last report*/
    unsigned long long inComingPktDelta;     /**< @brief Incoming data(packets) after last report*/
    unsigned long long outGoingPktDelta;     /**< @brief Outgoing data(packets) after last report*/

    time_t last_updated;        /**< @brief Last update of the counters */
} t_counters;

/** Client node for the connected client linked list.
 */
typedef struct _t_client {
    struct _t_client *next;             /**< @brief Pointer to the next client */
    unsigned long long id;              /**< @brief Unique ID per client */
    unsigned long long pass_time;            /**< @brief online time in milliseconds, format 1425956214241 */
    char ip[MAX_IP_ADDR_LEN];           /**< @brief Client Ip address, format AAA.BBB.CCC.DDD */
    char mac[MAX_MAC_ADDR_LEN];         /**< @brief Client Mac address, format aa:bb:cc:dd:ee:ff */
    char phone[MAX_PHONE_LEN];          /**< @brief Phone Numbers, format 13000010000 */
    char type[MAX_USER_TYPE_LEN];       /**< @brief Terminal Type, format Android, IOS, PC, etc. */
    char token[MAX_TOKEN_LEN];          /**< @brief Client token, format 1234 */
    char record_id[MAX_RECORD_ID_LEN];  /**< @brief Record Id in auth system, format 1 */
    int fw_connection_state;            /**< @brief Connection state in the firewall */
    //int fd;                           /**< @brief Client HTTP socket (valid only during login before one of the _http_* function is called */
    t_counters counters;                /**< @brief Counters for input/output of the client */
    bool need_free;
} t_client;

/** Client node for the connected client linked list.
 */
typedef struct _t_client_list {
    t_client *first;         /**< @brief Pointer to the first client */
    unsigned int eleNum;             /**< @brief Number of client list element */
    unsigned long long allocCnt;     /**< @brief Count of client list element allocate statistcs */
    unsigned long long freeCnt;       /**< @brief Count of client list element release statistcs */
    char name[20];
    pthread_mutex_t mutex;
} t_client_list;

/** @brief Get a new client from client resource pool */
t_client* client_alloc(void);

/** @brief return a client to client resource pool */
void client_release(t_client* client);

/** @brief Get a new client struct, not added to the list yet */
t_client *client_get_new(void);

/** @brief Get the first element of the list of connected clients */
t_client *client_get_first_client(void);

t_client_list* client_get_allocated_list(void);

t_client_list* client_get_free_list(void);


/** @brief Initializes the client list */
void client_list_init(unsigned int num);

/** @brief Insert client at head of list */
void client_list_insert_client(t_client *);

/** @brief Destroy the client list. Including all free... */
void client_list_destroy(t_client *);

/** @brief Adds a new client to the connections list */
t_client* client_list_add(const char* ip, const char* mac, const char* phone, const char* type, const char* record_id, const char* token);

/** Duplicate the whole client list to process in a thread safe way */
int client_list_dup(t_client **);

/** @brief Create a duplicate of a client. */
t_client *client_dup(const t_client *);

/** @brief Finds a client by its IP and MAC */
t_client *client_list_find(const char *, const char *);

/** @brief Find a client in the list from a client struct, matching operates by id. */
t_client *client_list_find_by_client(t_client *);

/** @brief Finds a client only by its IP */
t_client *client_list_find_by_ip(const char *); /* needed by fw_iptables.c, auth.c and wdctl_thread.c */

/** @brief Update a client with its new phone number, record_id or token */
t_client* client_update(t_client* src, const char* phone, const char* type, const char* record_id, const char* token, unsigned long long pass_time);

/** @brief Finds a client only by its Mac */
t_client *client_list_find_by_mac(const char *);        /* needed by wdctl_thread.c */

/** @brief Finds a client by its token */
t_client *client_list_find_by_token(const char *);

/** @brief Free memory associated with a client */
void client_free_node(t_client *);

/** @brief Deletes a client from the connections list and frees its memory*/
void client_list_delete(t_client *);

/** @brief Removes a client from the connections list */
bool client_list_remove(t_client *);

/** @brief show statistics of all lists */
char* client_show_all_list();

#define CLIENT_COPY_FIELD(dstClient, dstField, srcField) do { \
    if(srcField && dstClient) \
    { \
        memset(dstClient->dstField, 0, sizeof(dstClient->dstField)); \
        strncpy(dstClient->dstField, (srcField), sizeof(dstClient->dstField)-1); \
    } \
} while (0)

#ifdef USE_NEW_LOCK
#define LOCK_CLIENT_POOL(list) do { \
    debug(LOG_TRACE, "Locking client list %s@func:%s", ((t_client_list*)list)->name, __func__); \
    pthread_mutex_lock(&(((t_client_list*)list)->mutex)); \
    debug(LOG_TRACE, "Client list %s locked@func:%s", ((t_client_list*)list)->name, __func__); \
} while (0)

#define UNLOCK_CLIENT_POOL(list) do { \
    debug(LOG_TRACE, "Unlocking client list %s@func:%s", ((t_client_list*)list)->name, __func__); \
    pthread_mutex_unlock(&(((t_client_list*)list)->mutex)); \
    debug(LOG_TRACE, "Client list %s unlocked@func:%s", ((t_client_list*)list)->name, __func__); \
} while (0)

#define LOCK_CLIENT_LIST() 
#define UNLOCK_CLIENT_LIST() 
#else
#define LOCK_CLIENT_POOL(list) 
#define UNLOCK_CLIENT_POOL(list) 

#define LOCK_CLIENT_LIST() do { \
    debug(LOG_TRACE, "Locking client list@func:%s", __func__); \
    pthread_mutex_lock(&client_list_mutex); \
    debug(LOG_TRACE, "Client list locked@func:%s", __func__); \
} while (0)

#define UNLOCK_CLIENT_LIST() do { \
    debug(LOG_TRACE, "Unlocking client list@func:%s", __func__); \
    pthread_mutex_unlock(&client_list_mutex); \
    debug(LOG_TRACE, "Client list unlocked@func:%s", __func__); \
} while (0)
#endif
#endif /* _CLIENT_LIST_H_ */

