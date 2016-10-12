/* vim: set sw=4 ts=4 sts=4 et : */
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
/** @file agent_thread.c
    @brief Periodically checks in with the central auth server so the auth
    server knows the gateway is still up.  Note that this is NOT how the gateway
    detects that the central server is still up.
    @author Copyright (C) 2016 Coco.ke <coco.ke@ruhaoyi.com>
*/

#include "common.h"
#include "debug.h"
#include "agent_thread.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "../config.h"
#include "safe.h"
#include "conf.h"


#include "centralserver.h"
#include "wd_util.h"
#include "util.h"
#include "firewall.h"
#include "gateway.h"
#include "simple_http.h"
#include "cJSON.h"

#define SIZEOF_SVCPKT_DIST      (int)RHY_SIZEOF(T_SERVICEPACKETHDR, distinguisher)        /*4*/
#define SIZEOF_SVCPKT_XID       (int)RHY_SIZEOF(T_SERVICEPACKETHDR, xid)                  /*4*/
#define SIZEOF_SVCPKT_TYPE      (int)RHY_SIZEOF(T_SERVICEPACKETHDR, type)                 /*1*/
#define SIZEOF_SVCPKT_LENGTH    (int)RHY_SIZEOF(T_SERVICEPACKETHDR, length)               /*4*/
#define OFFSETOF_SVCPKT_LENGTH  (int)RHY_OFFSETOF(T_SERVICEPACKETHDR, length)             /*9*/
#define SIZEOF_SVCPKT_MGMT_HEAD (SIZEOF_SVCPKT_DIST+SIZEOF_SVCPKT_XID+SIZEOF_SVCPKT_TYPE+SIZEOF_SVCPKT_LENGTH)
#define MAX_PACKET_LEN MAX_BUF

typedef struct _ServicePacket {
    T_SERVICEPACKETHDR head;
    char data[MAX_PACKET_LEN];
}_RHY_PACKED T_SERVICEPACKET;

typedef struct _PacketHandleMgmt {
    pfSvcTypeCallBack pktHandler[E_TYPE_MAX];
}T_PACKETHANDLEMGMT;

#define MAX_RING_BUF_LEN (2*MAX_BUF)
typedef struct _RingBuf {
    int head;
    int rear;
    char buf[MAX_RING_BUF_LEN];
}T_RINGBUF;

extern void get_ext_iface_ip_until_success(char* extIpaddrBuf, int bufLen);

void ringBufInit(T_RINGBUF* pRingBuf)
{
    pRingBuf->head = 0;
    pRingBuf->rear = -1;
    memset(pRingBuf->buf, 0, sizeof(pRingBuf->buf));
}

int getRingBufLen(T_RINGBUF* pRingBuf)
{
    if(pRingBuf->rear==-1)
        return 0;

    return pRingBuf->rear>pRingBuf->head? pRingBuf->rear-pRingBuf->head+1:pRingBuf->rear+MAX_RING_BUF_LEN-pRingBuf->head+1;
}

int getRingBufTotalSpace(T_RINGBUF* pRingBuf)
{
    return MAX_RING_BUF_LEN;
}

int getRingBufFreeSpace(T_RINGBUF* pRingBuf)
{
    if(pRingBuf->rear==-1)
        return MAX_RING_BUF_LEN;

    if(pRingBuf->rear > pRingBuf->head)
        return MAX_RING_BUF_LEN-pRingBuf->rear+pRingBuf->head-1;
    else
        return pRingBuf->head-pRingBuf->rear-1;
}

/*将收到的一个TCP消息拷贝入Buf*/
bool putBuf2RingBuf(T_RINGBUF* pRingBuf, void* buf, int len)
{
    //int new_rear,len1,copylen;
    int len1,copylen;

    len1=getRingBufFreeSpace(pRingBuf);
    if(len > len1) return FALSE;

    if(pRingBuf->rear+len>=MAX_RING_BUF_LEN)
    {  //分两段拷贝rear - MAX_RING_BUF_LEN, 0 - 其余
        copylen = MAX_RING_BUF_LEN-pRingBuf->rear-1;
        memcpy(&pRingBuf->buf[pRingBuf->rear>=0?pRingBuf->rear+1:pRingBuf->head],buf,copylen);
        memcpy(pRingBuf->buf,(char *)buf+copylen,len-copylen);
    }
    else
    {
        memcpy(&pRingBuf->buf[pRingBuf->rear+1],buf,len);
    }

    //移动尾部指针
    pRingBuf->rear = ((pRingBuf->rear>=0)?(pRingBuf->rear+len):(pRingBuf->head+len-1)) % MAX_RING_BUF_LEN;
    return TRUE;
}

//读取一个TLV报文
int pullPacketfromRingBuf(T_RINGBUF* pRingBuf, void *buf, int len)
{
    int pktlen = 0;
    union data_{
        char lenStr[4];
        unsigned long length;
    }u_data;
    int copylen;
    int total_len = getRingBufLen(pRingBuf);
    if(total_len<SIZEOF_SVCPKT_MGMT_HEAD)
        return 0;

    memset(&u_data, 0, sizeof(u_data));
    if(pRingBuf->head>(MAX_RING_BUF_LEN-SIZEOF_SVCPKT_MGMT_HEAD) && pRingBuf->head<(MAX_RING_BUF_LEN-OFFSETOF_SVCPKT_LENGTH))
    {  //分两段拷贝rear - MAX_RING_BUF_LEN, 0 - 其余
        copylen = MAX_RING_BUF_LEN-(pRingBuf->head+OFFSETOF_SVCPKT_LENGTH);
        memcpy(u_data.lenStr, &pRingBuf->buf[pRingBuf->head+OFFSETOF_SVCPKT_LENGTH], copylen);
        memcpy(&u_data.lenStr[copylen], &pRingBuf->buf[0], SIZEOF_SVCPKT_LENGTH-copylen);
    }
    else
    {
        memcpy(u_data.lenStr, &pRingBuf->buf[pRingBuf->head+OFFSETOF_SVCPKT_LENGTH], SIZEOF_SVCPKT_LENGTH);
    }

    //先计算消息长度
    pktlen= ntohl(u_data.length)+SIZEOF_SVCPKT_MGMT_HEAD;
   // printf("pktlen %d, total_len %d\n",pktlen, total_len);
    
    /*报文超长或超短，出错了*/
    if(pktlen>len)
    {
        ringBufInit(pRingBuf);//重新初始化
        return -1;
    }
    
    if(total_len>=pktlen)
    {
        if(pRingBuf->rear>pRingBuf->head)
        {
            memcpy(buf, &pRingBuf->buf[pRingBuf->head], pktlen);
        }
        else
        {
            int copydatalen = ((MAX_RING_BUF_LEN-pRingBuf->head)>=pktlen ? pktlen : (MAX_RING_BUF_LEN-pRingBuf->head));
            memcpy(buf, &pRingBuf->buf[pRingBuf->head], copydatalen);
            memcpy((char *)buf+copydatalen, pRingBuf->buf, pktlen-copydatalen);
        }

        if(total_len==pktlen)//已经清空
        {
            pRingBuf->head = 0;
            pRingBuf->rear=-1;
        }
        else
        {
            pRingBuf->head = (pRingBuf->head + pktlen) % MAX_RING_BUF_LEN;
        }

        return pktlen;
    }
    else
    {
        return 0;
    }
}

bool tcp_register_connection(int sockFd)
{
    cJSON* root=NULL;
    char* ParseJsonOut;
    tcp_request r;
    char external_address[MAX_IP_ADDR_LEN]={0};
    T_SERVICEPACKETHDR head = {"rhy", 0, E_TYPE_DEVICE_REGISTER, 0};

    debug(LOG_DEBUG, "Entering tcp_register_connection()");
    memset(&r, 0, sizeof(r));
    r.sock = sockFd;

    get_ext_iface_ip_until_success(external_address, sizeof(external_address));
    if(strncmp(config_get_config()->external_address, external_address, sizeof(external_address)))
    {
        CONFIG_SET(external_address, external_address);
    }
    
    root=cJSON_CreateObject();
    cJSON_AddItemToObject(root, "clientId", cJSON_CreateString(config_get_config()->place_code)); //take placecode as unique clientId
    cJSON_AddItemToObject(root, "ip", cJSON_CreateString(config_get_config()->external_address)); //deviceIp
    cJSON_AddItemToObject(root, "version", cJSON_CreateString(config_get_config()->version));     //version
    cJSON_AddItemToObject(root, "key", cJSON_CreateString(config_get_config()->httpdpassword));   //must be "rhy"
    
    ParseJsonOut = cJSON_Print(root);
    cJSON_Delete(root);
    debug(LOG_DEBUG, "tcp_register_connection JsonOut: %s", ParseJsonOut);

    //head.type = E_TYPE_DEVICE_REGISTER;
    head.xid = htonl((unsigned int)rand16());
    tcpSetResponseHead(&r, &head);
    tcpSetResponseData(&r, ParseJsonOut, strlen(ParseJsonOut));
    tcpOutputResponse(&r);
        
    if(ParseJsonOut)
        free(ParseJsonOut);
    return TRUE;
}

bool tcp_callback_register_resp(char* data, unsigned int lenth, tcp_request* r)
{
    if(*data == 0x30 && lenth == 1)
    {
        debug(LOG_INFO, "tcp_callback_register_resp success");
        return TRUE;
    }
    else
    {
        debug(LOG_ERR, "tcp_callback_register_resp failed(0x%x) and need to retry", *data);
        return tcp_register_connection(r->sock);
    }
}

char tcpFromHex(char c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'A' && c <= 'F' ? c - 'A' + 10 : c - 'a' + 10; /* accept small letters just in case */
}

char* tcpUnescape(char* str)
{
    char* p = str;
    char* q = str;

    if (!str)
        return ("");
    while (*p) {
        if (*p == '%') {
            p++;
            if (*p)
                *q = tcpFromHex(*p++) * 16;
            if (*p)
                *q = (*q + tcpFromHex(*p++));
            q++;
        } else {
            if (*p == '+') {
                *q++ = ' ';
                p++;
            } else {
                *q++ = *p++;
            }
        }
    }

    *q++ = 0;
    return str;
}

int tcpAddVariable(tcp_request* r, const char* name, const char* value)
{
    int curCnt;
    while (*name == ' ' || *name == '\t')
        name++;

    if(r && r->varCount<MAX_TCPREQ_VAR_NUM) 
    {
        curCnt = r->varCount;
        strncpy(r->variables[curCnt].name, name, sizeof(r->variables[curCnt].name)-1);
        strncpy(r->variables[curCnt].value, value, sizeof(r->variables[curCnt].value)-1);
        r->varCount++;
        return 0;
    }
    return -1;
}

tcpVar* tcpGetVariableByName(tcp_request* r, const char* name)
{
    int curCnt=0;

    while (curCnt < r->varCount) {
        if (strcmp(r->variables[curCnt].name, name) == 0)
            return &r->variables[curCnt];
        curCnt++;
    }
    return (NULL);
}

void tcpStoreHead(T_SERVICEPACKET* msgH, tcp_request* r)
{
    memcpy(r->head.distinguisher, msgH->head.distinguisher, sizeof(r->head.distinguisher));
    r->head.xid= msgH->head.xid;
    r->head.type = msgH->head.type;
    r->head.length = ntohl(msgH->head.length);
}

void tcpStoreData(char* query, unsigned int len, tcp_request* r)
{
    if ((E_TYPE_DEVICE_HB_ECHO == r->head.type) || (E_TYPE_RESET_OS == r->head.type))
    {
        return;
    }

    if(E_TYPE_REMOTE_LOGIN==r->head.type || E_TYPE_REMOTE_LOGOUT==r->head.type)  /* http format */
    {
        char* cp, *cp2, *var, *val, *tmpVal;
        char dup_query[MAX_BUF]={0};
        char varbuf[MAX_BUF]={0};
        var = varbuf;
        
        if (!query)
            return;
    
        strncpy(dup_query, query, sizeof(dup_query)-1);
        cp = dup_query;
        cp2 = var;
        val = NULL;
        while (*cp) {
            if (*cp == '=') {
                cp++;
                *cp2 = 0;
                val = cp;
                continue;
            }
            if (*cp == '&') {
                *cp = 0;
                tmpVal = tcpUnescape(val);
                tcpAddVariable(r, var, tmpVal);
                cp++;
                cp2 = var;
                val = NULL;
                continue;
            }
            if (val) {
                cp++;
            } else {
                *cp2 = *cp++;
                cp2++;
            }
        }
        if (val != NULL) {
            *cp = 0;
            tmpVal = tcpUnescape(val);
            tcpAddVariable(r, var, tmpVal);
        }
    }
    else /* json format */
    {
        cJSON* pJson = cJSON_Parse(query);
        if (!pJson) 
        {
            debug(LOG_ERR, "tcpStoreData[%s] JSON Parse Error before:\n%s\n", query, cJSON_GetErrorPtr());
            return;
        }
        
        while(pJson)
        {
            if(pJson->type==cJSON_String)
            {
                if(pJson->valuestring)
                tcpAddVariable(r, pJson->string, pJson->valuestring);
                pJson = pJson->next;  //only parse cJSON_String type of 1 subtree
            }
            else
            {
                pJson = pJson->child;  //only check next, which means only 1 level, no other subtree
            }
        }
    }
}

void tcpPrintData(tcp_request* r)
{
    int curCnt=0;

    debug(LOG_TRACE, "tcpPrintData var count:%d", r->varCount);
    while (curCnt < r->varCount) {
        debug(LOG_TRACE, "var[%d] name:%s, value:%s", curCnt, r->variables[curCnt].name, r->variables[curCnt].value);
        curCnt++;
    }
}

void tcpPrintOutPut(tcp_request* r)
{
    unsigned int curCnt=0;
    char Buf[MAX_BUF]={0};
    char* pOut = (char*)&r->resphead;
    
    while (curCnt < r->respLen+sizeof(r->resphead)) {
        snprintf(&Buf[curCnt*2], sizeof(Buf)-1-curCnt*2, "%02x", pOut[curCnt]&0x000000ff);
        curCnt++;
    }
    debug(LOG_TRACE, "tcpPrintOutPut: %u bytes sent:[%s]", curCnt, Buf);
}

void tcpSetResponseHead(tcp_request* r, T_SERVICEPACKETHDR* head)
{
    memcpy(&r->resphead, head, sizeof(T_SERVICEPACKETHDR));
}

void tcpSetResponseData(tcp_request* r, char* data, int len)
{
    if((unsigned int)len < sizeof(r->respValue))
    {
        if(len>0)
          memcpy(r->respValue, data, len);
        r->respLen = len;
        r->resphead.length = htonl(len);
    }
}

int tcpOutputResponse(tcp_request* r)
{
    tcpPrintOutPut(r);
#if defined(_WIN32)
    return send(r->sock, &r->resphead, r->respLen+sizeof(r->resphead), 0);
#else
    return write(r->sock, &r->resphead, r->respLen+sizeof(r->resphead));
#endif
}

static unsigned int gErrArray[300];
char* getConnErrSttStr()
{
    int i;
    static char ConnEstrBuff[501]={0};
    memset(ConnEstrBuff, 0, sizeof(ConnEstrBuff));

    snprintf(ConnEstrBuff, 13, "ConnErrStt:\n");

    for(i=0; i < 300; i++)
    {
        if(gErrArray[i])
        {
            if(i<256)
            {
                snprintf(ConnEstrBuff+strlen(ConnEstrBuff), 500-strlen(ConnEstrBuff), "%d-%s:%u\n", 
                    i, strerror(i), gErrArray[i]);
            }
            else if(i==256)
            {
                snprintf(ConnEstrBuff+strlen(ConnEstrBuff), 500-strlen(ConnEstrBuff), "%d-Other:%u\n", 
                    i, gErrArray[i]);
            }
            else if(i==258)
            {
                snprintf(ConnEstrBuff+strlen(ConnEstrBuff), 500-strlen(ConnEstrBuff), "%d-BufferOverFlow:%u\n", 
                    i, gErrArray[i]);
            }
            else if(i==259)
            {
                snprintf(ConnEstrBuff+strlen(ConnEstrBuff), 500-strlen(ConnEstrBuff), "%d-PktProcess:%u\n", 
                    i, gErrArray[i]);
            }
            else
            {
                snprintf(ConnEstrBuff+strlen(ConnEstrBuff), 500-strlen(ConnEstrBuff), "%d-OtherDef:%u\n", 
                    i, gErrArray[i]);
            }
        }
    }
    return ConnEstrBuff;
}

static T_RINGBUF gRingBuf;
static void connect_agent(void);
static int handle_connection(int sockfd);
static int setKeepAlive(int fd, int interval);
/** Launches a thread that periodically checks in with the auth server to perform heartbeat function.
@param arg NULL
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void thread_comm_agent(void *arg)
{
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;

    while (1) {
        /* Make sure we check the servers at the very begining */
        debug(LOG_TRACE, "Running thread_comm_agent()");
        connect_agent();

        /* Sleep for 10 seconds... */
        timeout.tv_sec = time(NULL) + 10;
        timeout.tv_nsec = 0;

        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);

        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);
    }
}

/** @internal
 * This function does the actual request.
 */
static void connect_agent(void)
{
    static int conn_agent_sockfd = -1;
    static int authdown = 0;
    t_auth_serv *auth_agt=NULL;
    int ret;
    
    debug(LOG_DEBUG, "Entering connect_agent()");

    if(conn_agent_sockfd < 0)
    {
        conn_agent_sockfd = connect_auth_agent();
        if (conn_agent_sockfd < 0) 
        {
            goto CONN_FAIL;
        }
        else
        {
            int got_authdown_ruleset = (NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1);
            if(got_authdown_ruleset)
                fw_set_authup();

            config_set_tcpsock(conn_agent_sockfd);
            tcp_register_connection(conn_agent_sockfd);
            setKeepAlive(conn_agent_sockfd, TCP_KEEPALIVE_INTERVAL); 
            ringBufInit(&gRingBuf);
            authdown = 0;
        }
    }

    ret = handle_connection(conn_agent_sockfd);
    if(ret < 0)
    {      
        debug(LOG_ALERT, "Auth agents tcp disconnect:%d, %d", ret, errno);
        if(ret == -1)
        {
            if(errno < 256)
              gErrArray[errno]++;
            else
              gErrArray[256]++;
        }
        else /* -2 or -3 */
        {
            if(ret > -43)
              gErrArray[256-ret]++;
            else
              gErrArray[299]++;
        }
    }

CONN_FAIL:
    /*
     * No auth agents for me to talk to
     */
    if (!authdown) {
        int got_authdown_ruleset = (NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1);
        if(got_authdown_ruleset)
            fw_set_authdown();
        authdown = 1;
        
        LOCK_CONFIG();
        if(conn_agent_sockfd >= 0 )
        {
            auth_agt=find_auth_agt_by_socket(conn_agent_sockfd);
            if(auth_agt)
            {
                mark_auth_offline2(auth_agt, false);
            }
            conn_agent_sockfd = -1;
        }
        UNLOCK_CONFIG();
    }
   
    return;
}

static T_PACKETHANDLEMGMT gPacketHandlerMgmt;
bool ProcessPacket(int sockFd, char* packeBuffer)
{
    tcp_request RqBuf;
    T_SERVICEPACKET *msgH = (T_SERVICEPACKET *)packeBuffer;
    if (packeBuffer == NULL)
    {
        return FALSE;
    }

    memset(&RqBuf, 0, sizeof(RqBuf));
    RqBuf.sock = sockFd;
    
    E_SERVICE_TYPE Type = (E_SERVICE_TYPE)(msgH->head.type);
    unsigned int Length = ntohl(msgH->head.length);
    if (Type >= E_TYPE_MAX || Type <= E_TYPE_MIN)
    {
        debug(LOG_ERR, "ProcessPacket Invalid Type = %d, Length = %u", Type, Length);
        return FALSE;
    }

    debug(LOG_TRACE, "ProcessPacket Xid=0x%x, Type=%d, Length=%u, Value=%s", ntohl(msgH->head.xid), Type, Length, msgH->data);
    tcpStoreHead(msgH, &RqBuf);
    tcpStoreData(msgH->data, Length, &RqBuf);
    tcpPrintData(&RqBuf);
    if(gPacketHandlerMgmt.pktHandler[Type])
        gPacketHandlerMgmt.pktHandler[Type](msgH->data, Length, &RqBuf);
    return TRUE;
}

static int handle_recv_msg(int sockFd, char* msgBuf, int msgLen, T_RINGBUF* pRingBuf) 
{
    int pktLen=0;
    int i;
    char packetBuf[MAX_PACKET_LEN]={0};
    char dbgBuf[MAX_GENERAL_LEN]={0};
    int  dbgLen = (msgLen>=SIZEOF_SVCPKT_MGMT_HEAD)? SIZEOF_SVCPKT_MGMT_HEAD:msgLen;
    int  leftLen = msgLen;
    char* pBuf = msgBuf;
    
    int printLen = snprintf(dbgBuf, sizeof(dbgBuf)-1, "RBuf head:%d, rear:%d, %d bytes:[", pRingBuf->head, pRingBuf->rear, msgLen);
    
    for(i = 0; i < dbgLen; i++)
    {
        if(i!=dbgLen-1)
        {
            printLen+=snprintf((dbgBuf + printLen), sizeof(dbgBuf)-1-printLen, "%02x ", pBuf[i]&0x000000ff);
        }
        else
        {
            printLen+=snprintf((dbgBuf + printLen), sizeof(dbgBuf)-1-printLen, "%02x", pBuf[i]&0x000000ff);
        }
    }
    debug(LOG_TRACE, "%s]", dbgBuf);
#if 0
    if(getRingBufLen(pRingBuf) == 0)
    {
        while(leftLen > SIZEOF_SVCPKT_MGMT_HEAD)
        {
            memcpy((char*)&pktLen, &pBuf[1], SIZEOF_SVCPKT_LENGTH);
            pktLen = ntohl(pktLen);
            if(pktLen <= leftLen-SIZEOF_SVCPKT_MGMT_HEAD)
            {
                if(ProcessPacket(sockFd, pBuf))
                {
                    leftLen = leftLen-SIZEOF_SVCPKT_MGMT_HEAD-pktLen;
                    pBuf   = pBuf  +SIZEOF_SVCPKT_MGMT_HEAD+pktLen;
                }
                else
                {
                    return -1;
                }
            }
            else
            {
                break;
            }
        }
    }
#endif
    if(0==leftLen)
    {
        return 0;
    }
    if(!putBuf2RingBuf(pRingBuf, pBuf, leftLen))
    {
        debug(LOG_ERR, "client fd[%d]: write %d bytes to ringbuffer but overflow", sockFd, leftLen);
        return -2;
    }
    debug(LOG_TRACE, "RingBuf head:%d, rear:%d", pRingBuf->head, pRingBuf->rear);
    pktLen = pullPacketfromRingBuf(pRingBuf, packetBuf, sizeof(packetBuf));
    debug(LOG_TRACE, "Read %d bytes from RingBuf, now head:%d, rear:%d", pktLen, pRingBuf->head, pRingBuf->rear);
    while(pktLen > 0)
    {
        if(ProcessPacket(sockFd, packetBuf))
        {
            memset(packetBuf, 0, sizeof(packetBuf));
            pktLen = pullPacketfromRingBuf(pRingBuf, packetBuf, sizeof(packetBuf));
        }
        else
        {
            debug(LOG_ERR, "client fd[%d]: ProcessPacket failed", sockFd);
            return -3;
        }
    }
    return pktLen;

}

static int handle_connection(int sockfd)
{
    char recvMsg[MAX_BUF];
    int maxfdp;
    fd_set readfds;
    int readLen;
    int retval = 0;
    int ret;
    
    while (1)
    {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        maxfdp = sockfd;
        #if 0
        struct timeval tv;
        tv.tv_sec = DAEMON_SELECT_SECONDS;
        tv.tv_usec = 0;
        
        retval = select(maxfdp+1, &readfds, NULL, NULL, &tv/*NULL*/); 
        if (retval == -1)
        {
            close(sockfd);
            FD_CLR(sockfd,&readfds);
            return -1;
        }
        
        if (retval == 0) 
        {
            continue;
        }
        #else
        retval = select(maxfdp+1, &readfds, NULL, NULL, NULL); 
        if (retval <= 0)
        {
            debug(LOG_ERR, "client fd[%d]: error ret:%d, errno:%d %s", sockfd, retval, errno, strerror(errno));
            close(sockfd);
            FD_CLR(sockfd,&readfds);
            return -1;
        }
        #endif
        if (FD_ISSET(sockfd, &readfds)) 
        {
            memset(recvMsg, 0, sizeof(recvMsg));
            readLen = read(sockfd, recvMsg, sizeof(recvMsg)-1);
            if (readLen == 0)
            {
                debug(LOG_INFO, "client fd[%d]: server is closed", sockfd);
                close(sockfd);
                FD_CLR(sockfd,&readfds);
                return -1;
            }
            else if (readLen < 0) //无数据可读，等待下一次消息循环
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    debug(LOG_INFO, "client fd[%d]: read from socket but no data, errno=%d", sockfd, errno);
                    continue;
                }
                else
                {
                    debug(LOG_ERR, "client fd[%d]: read from socket error, errno:%d %s", sockfd, errno, strerror(errno));
                    close(sockfd);
                    FD_CLR(sockfd,&readfds);
                    return -1;
                }
            }

            debug(LOG_TRACE, "client fd[%d]: read [%d] bytes from socket", sockfd, readLen);
            ret = handle_recv_msg(sockfd, recvMsg, readLen, &gRingBuf);
            if(ret < 0)
            {
                debug(LOG_ERR, "client fd[%d]: handle_recv_msg error", sockfd);
                close(sockfd);
                FD_CLR(sockfd,&readfds);
                return ret;
            }
        }
    }
}

/* Set TCP keep alive option to detect dead peers. The interval option 
 * is only used for Linux as we are using Linux-specific APIs to set 
 * the probe send time, interval, and count. */  
static int setKeepAlive(int fd, int interval)  
{  
    int val = 1;  
    //开启keepalive机制  
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) == -1)  
    {  
        debug(LOG_ERR, "setsockopt SO_KEEPALIVE: %s", strerror(errno));  
        return -1;  
    }  
 
    /* Default settings are more or less garbage, with the keepalive time 
     * set to 7200 by default on Linux. Modify settings to make the feature 
     * actually useful. */  
  
    /* Send first probe after interval. */  
    val = interval/5;  
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val)) < 0) {  
        debug(LOG_ERR, "setsockopt TCP_KEEPIDLE: %s", strerror(errno));  
        return -2;
    }
  
    /* Send next probes after the specified interval. Note that we set the 
     * delay as interval/5, as we send five probes before detecting 
     * an error (see the next setsockopt call). */  
    val = interval/5;
    if (val < 10) val = 10;  
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val)) < 0) {  
        debug(LOG_ERR, "setsockopt TCP_KEEPINTVL: %s", strerror(errno));  
        return -3;
    }  
  
    /* Consider the socket in error state after three we send three ACK 
     * probes without getting a reply. */  
    val = 5;  
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val)) < 0) {  
        debug(LOG_ERR, "setsockopt TCP_KEEPCNT: %s", strerror(errno));  
        return -4;
    } 
  
    return 0;
}  

bool registerPacketHandler(E_SERVICE_TYPE type, pfSvcTypeCallBack callBack)
{
    if (type >= E_TYPE_MAX || type <= E_TYPE_MIN)
    {
        debug(LOG_ERR, "registerPacketHandler invalid type = %d", type);
        return FALSE;
    }
    
    gPacketHandlerMgmt.pktHandler[type] = callBack;
    return TRUE;
}

