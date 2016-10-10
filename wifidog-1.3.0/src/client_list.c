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

/** @file client_list.c
  @brief Client List Functions
  @author Copyright (C) 2004 Alexandre Carmel-Veillex <acv@acv.ca>
 */

#define _GNU_SOURCE
#include "common.h"

#include <sys/wait.h>
#include <sys/types.h>
#include "safe.h"
#include "debug.h"
#include "util.h"
#include "conf.h"
#include "client_list.h"

/** @internal
 * Holds data struct of the lists 
 */
static t_client_list freeList={NULL, 0, 0, 0, "FreeList", PTHREAD_MUTEX_INITIALIZER};
static t_client_list usedList={NULL, 0, 0, 0, "UsedList", PTHREAD_MUTEX_INITIALIZER};
static t_client_list duplList={NULL, 0, 0, 0, "DuplList", PTHREAD_MUTEX_INITIALIZER};

#ifndef USE_NEW_LOCK
/** Mutex to protect client_id and guarantee uniqueness. */
static pthread_mutex_t client_id_mutex = PTHREAD_MUTEX_INITIALIZER;

/** Global mutex to protect access to the client list */
pthread_mutex_t client_list_mutex = PTHREAD_MUTEX_INITIALIZER;

/** Global mutex to protect access to the free client pool */
pthread_mutex_t client_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/** @internal Client ID */
static volatile unsigned long long client_id = 1;

#define LIST_SHOW_MAX_LEN 100

/** Get a new client struct, not added to the list yet
 * @return Pointer to newly created client object not on the list yet.
 */
inline static t_client* _alloc_client(t_client_list* list)
{
    t_client *client;
    unsigned long long id;
    if(!list)
        return NULL;
    LOCK_CLIENT_POOL(list);
    client = list->first;
    if(client)
    {
        list->first = client->next;
        list->eleNum--;
        list->allocCnt++;
        id = client->id;
        memset(client, 0, sizeof(t_client));
        client->id = id;
    }
    UNLOCK_CLIENT_POOL(list);
    
    return client;
}

inline static void _free_client(t_client_list* list, t_client* client)
{
    if(!list)
        return;
    LOCK_CLIENT_POOL(list);
    
    client->next = list->first;
    list->first = client;
    list->eleNum++;
    list->freeCnt++;
    UNLOCK_CLIENT_POOL(list);
}

inline static t_client* _first_client(t_client_list* list)
{
    if(!list)
        return NULL;
    return list->first;
}

inline static void _list_insert_client(t_client_list* list, t_client * client)
{
    t_client *prev_head;

    if(!list)
        return;
    LOCK_CLIENT_POOL(list);
    prev_head = list->first;
    client->next = prev_head;
    list->first = client;
    list->eleNum++;
    list->allocCnt++;
    UNLOCK_CLIENT_POOL(list);
}

inline static bool _list_remove_client(t_client_list* list, t_client* client)
{
    t_client *ptr;

    if(!list || !client)
    {
        debug(LOG_ERR, "client_remove_from_list: list[%p] or client[%p] is null", list, client);
        return false;
    }
    
    LOCK_CLIENT_POOL(list);
    ptr = list->first;
    if (ptr == NULL) 
    {
        UNLOCK_CLIENT_POOL(list);
        debug(LOG_ERR, "client_remove_from_list: list %s is empty", list->name);
        return false;
    }
    else if (ptr == client)
    {
        list->first = ptr->next;
        list->eleNum--;
        list->freeCnt++;
    }
    else
    {
        /* Loop forward until we reach our point in the list. */
        while (ptr->next != NULL && ptr->next != client) 
        {
            ptr = ptr->next;
        }
        /* If we reach the end before finding out element, complain. */
        if (ptr->next == NULL)
        {
            UNLOCK_CLIENT_POOL(list);
            debug(LOG_ERR, "client_remove_from_list cannot find out client[%s] from list %s", client->ip, list->name);
            return false;
        } 
        else 
        {
            ptr->next = client->next;
            list->eleNum--;
            list->freeCnt++;
        }
    }
    
    UNLOCK_CLIENT_POOL(list);
    return true;
}

inline static void _client_list_show(t_client_list* clist, char* buff)
{
    if(!clist)
    {
        return;
    }

    snprintf(buff, LIST_SHOW_MAX_LEN, "List:%s, ElementCount:%u, AllocateTimes:%llu, ReleaseTimes:%llu\n", 
                    clist->name, clist->eleNum, clist->allocCnt, clist->freeCnt);
}

t_client* client_alloc(void)
{    
    return _alloc_client(&freeList);
}

void client_release(t_client* client)
{
    _free_client(&freeList, client);
}

t_client* client_get_new(void)
{
    t_client *client;
    client = _alloc_client(&duplList);
    
    return client;
}

/** Get the first element of the list of connected clients
 */
t_client* client_get_first_client(void)
{
    return _first_client(&usedList);
}

t_client_list* client_get_allocated_list(void)
{
    return &usedList;
}

t_client_list* client_get_free_list(void)
{
    return &freeList;
}

/**
 * Initializes the list of connected clients
 */
void client_list_init(unsigned int num)
{
    unsigned int i;
    t_client* client;
    t_client* pClientPool;
    t_client* prev_head;

    pClientPool = safe_malloc(sizeof(t_client)*num);
    LOCK_CLIENT_POOL(&freeList);
    for(i=0; i < num; i++)
    {
        client = pClientPool + i;
        client->id = num - i;
        prev_head = freeList.first;
        client->next = prev_head;
        freeList.first = client;
        freeList.eleNum++;
    }
    UNLOCK_CLIENT_POOL(&freeList);

    //nothing to do with usedList at all;

    pClientPool = safe_malloc(sizeof(t_client)*(2*num+8));
    LOCK_CLIENT_POOL(&duplList);
    for(i=0; i < 2*num+8; i++)
    {
        client = pClientPool + i;
        //client->id = 0; //don't care about it;
        prev_head = duplList.first;
        client->next = prev_head;
        duplList.first = client;
        duplList.eleNum++;
    }
    UNLOCK_CLIENT_POOL(&duplList);
}

/** Insert client at head of list. Lock should be held when calling this!
 * @param Pointer to t_client object.
 */
void client_list_insert_client(t_client * client)
{
    _list_insert_client(&usedList, client);
}

/** Based on the parameters it receives, this function creates a new entry
 * in the connections list. All the memory allocation is done here.
 * Client is inserted at the head of the list.
 * @param ip IP address
 * @param mac MAC address
 * @param token Token
 * @return Pointer to the client we just created
 */
t_client* client_list_add(const char* ip, const char* mac, const char* phone, const char* type, const char* record_id, const char* token)
{
    t_client *curclient;

    curclient = client_alloc();
    if(curclient)
    {
        curclient->pass_time = get_millisecond();
        CLIENT_COPY_FIELD(curclient, ip, ip);
        CLIENT_COPY_FIELD(curclient, mac, mac);
        CLIENT_COPY_FIELD(curclient, phone, phone);
        CLIENT_COPY_FIELD(curclient, type, type);
        CLIENT_COPY_FIELD(curclient, token, token);
        CLIENT_COPY_FIELD(curclient, record_id, record_id);
        memset(&curclient->counters, 0, sizeof(curclient->counters));
        curclient->counters.last_updated = time(NULL);
    
        client_list_insert_client(curclient);
        debug(LOG_INFO, "Added a new client: [IP:%s, MAC:%s, Phone:%s, Type:%s, Token:%s, Record:%s]", 
                        ip, mac, phone, type, token, record_id);
    }
    else
    {
        debug(LOG_NOTICE, "Coming a new client[IP:%s, MAC:%s, Phone:%s, Type:%s, Token:%s, Record:%s], but no enough resource",
                        ip, mac, phone, type, token, record_id);
    }
    return curclient;
}

/** Duplicate the whole client list to process in a thread safe way
 * MUTEX MUST BE HELD.
 * @param dest pointer TO A POINTER to a t_client (i.e.: t_client **ptr)
 * @return int Number of clients copied
 */
int client_list_dup(t_client** dest)
{
    t_client *new, *cur, *top, *prev;
    int copied = 0;

    new = top = prev = NULL;
    
    LOCK_CLIENT_POOL(&usedList);
    cur = usedList.first;
    
    if (NULL == cur) {
        goto BailOut;
    }

    while (NULL != cur) 
    {
        new = client_dup(cur);
        if (NULL == top)
        {
            /* first item */
            top = new;
        } 
        else if(prev)
        {
            prev->next = new;
        }
        prev = new;
        copied++;
        cur = cur->next;
    }

BailOut:
    UNLOCK_CLIENT_POOL(&usedList);
    *dest = top;
    return copied;
}

/** Create a duplicate of a client.
 * @param src original client
 * @return duplicate client object with next == NULL
 */
t_client* client_dup(const t_client* src)
{
    t_client *new = NULL;
    
    if (NULL == src) {
        return NULL;
    }
    
    new = client_get_new();
    if(new)
    {
        new->id = src->id;
        new->pass_time = src->pass_time;
        CLIENT_COPY_FIELD(new, ip, src->ip);
        CLIENT_COPY_FIELD(new, mac, src->mac);
        CLIENT_COPY_FIELD(new, phone, src->phone);
        CLIENT_COPY_FIELD(new, type, src->type);
        CLIENT_COPY_FIELD(new, token, src->token);
        CLIENT_COPY_FIELD(new, record_id, src->record_id);
        new->fw_connection_state = src->fw_connection_state;
        memcpy(&new->counters, &src->counters, sizeof(t_counters));
        new->need_free = true;
        new->next = NULL; 
    }
    return new;
}

/** Find a client in the list from a client struct, matching operates by id.
 * This is useful from a copy of client to find the original.
 * @param client Client to find
 * @return pointer to the client in the list.
 */
t_client* client_list_find_by_client(t_client* client)
{
    t_client *c;

    LOCK_CLIENT_POOL(&usedList);
    c = usedList.first;
    while (NULL != c) 
    {
        if (c->id == client->id) 
        {
            UNLOCK_CLIENT_POOL(&usedList);
            return c;
        }
        c = c->next;
    }

    UNLOCK_CLIENT_POOL(&usedList);
    return NULL;
}

/** Finds a  client by its IP and MAC, returns NULL if the client could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @param mac MAC we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client* client_list_find(const char* ip, const char* mac)
{
    t_client *ptr;

    LOCK_CLIENT_POOL(&usedList);
    ptr = usedList.first;
    while (NULL != ptr) 
    {
        if (0 == strcmp(ptr->ip, ip) && 0 == strcmp(ptr->mac, mac))
        {
            UNLOCK_CLIENT_POOL(&usedList);
            return ptr;
        }
        ptr = ptr->next;
    }

    UNLOCK_CLIENT_POOL(&usedList);
    return NULL;
}

t_client* client_update(t_client* src, const char* phone, const char* type, const char* record_id, const char* token, unsigned long long pass_time)
{
    if(src)
    {
        CLIENT_COPY_FIELD(src, phone, phone);
        CLIENT_COPY_FIELD(src, type, type);
        CLIENT_COPY_FIELD(src, record_id, record_id);
        CLIENT_COPY_FIELD(src, token, token);
        
        if(pass_time)
        {
            src->pass_time = pass_time;
        }
    }
    return src;
}

/**
 * Finds a  client by its IP, returns NULL if the client could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client* client_list_find_by_ip(const char* ip)
{
    t_client *ptr;

    LOCK_CLIENT_POOL(&usedList);
    ptr = usedList.first;
    while (NULL != ptr) 
    {
        if (0 == strcmp(ptr->ip, ip))
        {
            UNLOCK_CLIENT_POOL(&usedList);
            return ptr;
        }
        ptr = ptr->next;
    }

    UNLOCK_CLIENT_POOL(&usedList);
    return NULL;
}

/**
 * Finds a  client by its Mac, returns NULL if the client could not
 * be found
 * @param mac Mac we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client* client_list_find_by_mac(const char* mac)
{
    t_client *ptr;

    LOCK_CLIENT_POOL(&usedList);
    ptr = usedList.first;
    while (NULL != ptr)
    {
        if (0 == strcmp(ptr->mac, mac))
        {
            UNLOCK_CLIENT_POOL(&usedList);
            return ptr;
        }
        ptr = ptr->next;
    }

    UNLOCK_CLIENT_POOL(&usedList);
    return NULL;
}

/** Finds a client by its token
 * @param token Token we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client* client_list_find_by_token(const char* token)
{
    t_client *ptr;

    LOCK_CLIENT_POOL(&usedList);
    ptr = usedList.first;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->token, token))
        {
            UNLOCK_CLIENT_POOL(&usedList);
            return ptr;
        }
        ptr = ptr->next;
    }

    UNLOCK_CLIENT_POOL(&usedList);
    return NULL;
}

/** Destroy the client list. Including all free...
 * DOES NOT UPDATE usedList.first or anything else.
 * @param list List to destroy (first item)
 */
void client_list_destroy(t_client* list)
{
    t_client *next;

    while (NULL != list) {
        next = list->next;
        client_free_node(list);
        list = next;
    }
}

/** @internal
 * @brief Frees the memory used by a t_client structure
 * This function frees the memory used by the t_client structure in the
 * proper order.
 * @param client Points to the client to be freed
 */
void client_free_node(t_client* client)
{
    unsigned long long id;
    bool need_free;
    if(client)
    {
        id = client->id;
        need_free = client->need_free;
        memset(client, 0, sizeof(t_client));
        if(need_free)
        {
            _free_client(&duplList, client);
        }
        else
        {
            client->id = id;
            client_release(client);
        }
    }
}

/**
 * @brief Deletes a client from the connections list
 *
 * Removes the specified client from the connections list and then calls
 * the function to free the memory used by the client.
 * @param client Points to the client to be deleted
 */
void client_list_delete(t_client* client)
{
    client_list_remove(client);
    client_free_node(client);
}

/**
 * @brief Removes a client from the connections list
 *
 * @param client Points to the client to be deleted
 */
bool client_list_remove(t_client* client)
{   
    return _list_remove_client(&usedList, client);
}

char* client_show_all_list()
{
    static char buff[3*LIST_SHOW_MAX_LEN+1]={0};
    memset(buff, 0, sizeof(buff));
    _client_list_show(&usedList, buff);
    _client_list_show(&freeList, buff+strlen(buff));
    _client_list_show(&duplList, buff+strlen(buff));
    return buff;
}

