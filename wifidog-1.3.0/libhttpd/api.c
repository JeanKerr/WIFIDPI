/* vim: tabstop=4 softtabstop=4 shiftwidth=4 expandtab
** Copyright (c) 2002  Hughes Technologies Pty Ltd.  All rights
** reserved.
**
** Terms under which this software may be used or copied are
** provided in the  specific license associated with this product.
**
** Hughes Technologies disclaims all warranties with regard to this
** software, including all implied warranties of merchantability and
** fitness, in no event shall Hughes Technologies be liable for any
** special, indirect or consequential damages or any damages whatsoever
** resulting from loss of use, data or profits, whether in an action of
** contract, negligence or other tortious action, arising out of or in
** connection with the use or performance of this software.
**
**
** $Id$
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

#define SO_REUSEADDR

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <unistd.h>
#include <sys/file.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

#include "config.h"
#include "httpd.h"
#include "httpd_priv.h"

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

typedef struct _HTTPMETHODMAPS{
    const char *name;
    t_httpmethod method;
}T_HTTPMETHODMAPS;


static const T_HTTPMETHODMAPS methodmaps[HTTP_METHOD_MAX] = {
    {"UNKOWN",  HTTP_UNKOWN}, 
    {"GET",     HTTP_GET}, 
    {"HEAD",    HTTP_HEAD}, 
    {"PUT",     HTTP_PUT}, 
    {"DELETE",  HTTP_DELETE}, 
    {"POST",    HTTP_POST}, 
    {"OPTIONS", HTTP_OPTIONS}, 
    {"TRACE",   HTTP_TRACE}, 
    {"CONNECT", HTTP_CONNECT},
    {"NOTIFY",  HTTP_NOTIFY}
};

char* httpdUrlEncode(const char* str)
{
    char* new, *cp;

    new = (char* )_httpd_escape(str);
    if (new == NULL) {
        return (NULL);
    }
    cp = new;
    while (*cp) {
        if (*cp == ' ')
            *cp = '+';
        cp++;
    }
    return (new);
}

char* httpdMethod2Name(t_httpmethod method, char* MethodStr, size_t length)
{
    unsigned int i = 0;
    
    memset(MethodStr, 0, length);  /* nessisary due to no MethodStr[HTTP_METHOD_MAX_LEN-1]=0; */
    for(; i < sizeof(methodmaps)/sizeof(T_HTTPMETHODMAPS); i++) 
    {
        if(methodmaps[i].method == method)
        {
            strncpy(MethodStr, methodmaps[i].name, length-1);
            return MethodStr;
        }
    }
    
    snprintf(MethodStr, length-1, "InvalidMethod:%d", method);  /* size should be < HTTP_METHOD_MAX_LEN */
    return MethodStr;
}

t_httpmethod httpdGetMethodbyName(char* cp)
{
    unsigned int i = 1;
    
    for(; i < sizeof(methodmaps)/sizeof(T_HTTPMETHODMAPS); i++) 
    {
        if(strcasecmp(cp, methodmaps[i].name) == 0)
            return methodmaps[i].method;
    }
    
    return HTTP_UNKOWN;
}

httpVar* httpdGetVariableByName(request* r, const char* name)
{
    httpVar* curVar;

    curVar = r->variables;
    while (curVar) {
        if (strcmp(curVar->name, name) == 0)
            return (curVar);
        curVar = curVar->nextVariable;
    }
    return (NULL);
}

httpVar* httpdGetVariableByPrefix(request* r, const char* prefix)
{
    httpVar* curVar;

    if (prefix == NULL)
        return (r->variables);
    curVar = r->variables;
    while (curVar) {
        if (strncmp(curVar->name, prefix, strlen(prefix)) == 0)
            return (curVar);
        curVar = curVar->nextVariable;
    }
    return (NULL);
}

int httpdSetVariableValue(request* r, const char* name, const char* value)
{
    httpVar* var;

    var = httpdGetVariableByName(r, name);
    if (var) {
        if (var->value)
            free(var->value);
        var->value = strdup(value);
        return (0);
    } else {
        return (httpdAddVariable(r, name, value));
    }
}

httpVar* httpdGetVariableByPrefixedName(request* r, const char* prefix, const char* name)
{
    httpVar* curVar;
    int prefixLen;

    if (prefix == NULL)
        return (r->variables);
    curVar = r->variables;
    prefixLen = strlen(prefix);
    while (curVar) {
        if (strncmp(curVar->name, prefix, prefixLen) == 0 && strcmp(curVar->name + prefixLen, name) == 0) {
            return (curVar);
        }
        curVar = curVar->nextVariable;
    }
    return (NULL);
}

httpVar* httpdGetNextVariableByPrefix(httpVar* curVar, const char* prefix)
{
    if (curVar)
        curVar = curVar->nextVariable;
    while (curVar) {
        if (strncmp(curVar->name, prefix, strlen(prefix)) == 0)
            return (curVar);
        curVar = curVar->nextVariable;
    }
    return (NULL);
}

int httpdAddVariable(request* r, const char* name, const char* value)
{
    httpVar* curVar, *lastVar, *newVar;

    while (*name == ' ' || *name == '\t')
        name++;
    newVar = malloc(sizeof(httpVar));
    bzero(newVar, sizeof(httpVar));
    newVar->name = strdup(name);
    newVar->value = strdup(value);
    lastVar = NULL;
    curVar = r->variables;
    while (curVar) {
        if (strcmp(curVar->name, name) != 0) {
            lastVar = curVar;
            curVar = curVar->nextVariable;
            continue;
        }
        while (curVar) {
            lastVar = curVar;
            curVar = curVar->nextValue;
        }
        lastVar->nextValue = newVar;
        return (0);
    }
    if (lastVar)
        lastVar->nextVariable = newVar;
    else
        r->variables = newVar;
    return (0);
}

httpd* httpdCreate(char* host, int port, char* webname)
{
    httpd* new;
    int sock, opt;
    struct sockaddr_in addr;
    char rootStr[HTTP_MAX_BUFFER_SIZE]={0};
    /*
     ** Create the handle and setup it's basic config
     */
    new = malloc(sizeof(httpd));
    if (new == NULL)
        return (NULL);
    bzero(new, sizeof(httpd));
    strncpy(new->name, webname, sizeof(new->name)-1);
    new->port = port;
    if (host == HTTP_ANY_ADDR)
        strncpy(new->host, "0.0.0.0", sizeof(new->host)-1);
    else
        strncpy(new->host, host, sizeof(new->host)-1);
    new->content = (httpDir* ) malloc(sizeof(httpDir));
    bzero(new->content, sizeof(httpDir));
    snprintf(rootStr, sizeof(rootStr)-1, "%s:%d", host, port);
    strncpy(new->content->name, rootStr, sizeof(new->content->name)-1);

    /*
     ** Setup the socket
     */
#ifdef _WIN32
    {
        WORD wVersionRequested;
        WSADATA wsaData;
        int err;

        wVersionRequested = MAKEWORD(2, 2);

        err = WSAStartup(wVersionRequested, &wsaData);

        /* Found a usable winsock dll? */
        if (err != 0)
            return NULL;

        /* 
         ** Confirm that the WinSock DLL supports 2.2.
         ** Note that if the DLL supports versions greater 
         ** than 2.2 in addition to 2.2, it will still return
         ** 2.2 in wVersion since that is the version we
         ** requested.
         */

        if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {

            /* 
             ** Tell the user that we could not find a usable
             ** WinSock DLL.
             */
            WSACleanup();
            return NULL;
        }

        /* The WinSock DLL is acceptable. Proceed. */
    }
#endif

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        free(new);
        return (NULL);
    }
#ifdef SO_REUSEADDR
    opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char* )&opt, sizeof(int)) < 0) {
        close(sock);
        free(new);
        return NULL;
    }
#endif
    new->serverSock = sock;
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    if (new->host == HTTP_ANY_ADDR) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        addr.sin_addr.s_addr = inet_addr(new->host);
    }
    addr.sin_port = htons((u_short) new->port);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        free(new);
        return (NULL);
    }
    listen(sock, 128);
    new->startTime = time(NULL);
    return (new);
}

void httpdDestroy(httpd* server)
{
    if (server == NULL)
        return;
    free(server);
}

request *httpdGetConnection(httpd* server, struct timeval* timeout)
{
    int result;
    fd_set fds;
    struct sockaddr_in addr;
    socklen_t addrLen;
    char* ipaddr;
    request *r;
    /* Reset error */
    server->lastError = 0;
    FD_ZERO(&fds);
    FD_SET(server->serverSock, &fds);
    result = 0;
    while (result == 0) {
        result = select(server->serverSock + 1, &fds, 0, 0, timeout);
        if (result < 0) {
            server->lastError = -1;
            return (NULL);
        }
        if (timeout != 0 && result == 0) {
            server->lastError = 0;
            return (NULL);
        }
        if (result > 0) {
            break;
        }
    }
    /* Allocate request struct */
    r = (request *) malloc(sizeof(request));
    if (r == NULL) {
        server->lastError = -3;
        return (NULL);
    }
    memset((void *)r, 0, sizeof(request));
    /* Get on with it */
    bzero(&addr, sizeof(addr));
    addrLen = sizeof(addr);
    r->clientSock = accept(server->serverSock, (struct sockaddr *)&addr, &addrLen);
    ipaddr = inet_ntoa(addr.sin_addr);
    if (ipaddr) {
        strncpy(r->clientAddr, ipaddr, sizeof(r->clientAddr)-1);
        r->clientAddr[sizeof(r->clientAddr)-1] = 0;
    } else
        *r->clientAddr = 0;
    r->readBufRemain = 0;
    r->readBufPtr = NULL;

    /*
     ** Check the default ACL
     */
    if (server->defaultAcl) {
        if (httpdCheckAcl(server, r, server->defaultAcl)
            == HTTP_ACL_DENY) {
            httpdEndRequest(r);
            server->lastError = 2;
            return (NULL);
        }
    }
    return (r);
}

extern int _httpd_decode(char* bufcoded, char* bufplain, int outbufsize);
int httpdReadRequest(httpd* server, request* r)
{
    char buf[HTTP_READ_BUF_LEN];
    int count, inHeaders;
    char* cp, *cp2;
    int ret;
    /*
     ** Setup for a standard response
     */
    strncpy(r->response.headers, "RHY Server: www.ruhaoyi.com\n", sizeof(r->response.headers)-1);
    strncpy(r->response.contentType, "text/html", sizeof(r->response.contentType)-1);
    strncpy(r->response.response, "200 Output Follows\n", sizeof(r->response.response)-1);
    r->response.headersSent = 0;

    /*
     ** Read the request
     */
    count = 0;
    inHeaders = 1;
    while((ret = _httpd_readLine(r, buf, HTTP_READ_BUF_LEN)) > 0) 
    {
        count++;

        /* Special case for the first line.  Scan the request method and path etc */
        if (count == 1) {
            /* Request Method: GET */
            cp = cp2 = buf;
            while (isalpha((unsigned char)*cp2))
                cp2++;
            *cp2 = 0;
            httpdRequestMethod(r) = httpdGetMethodbyName(cp);
            if (httpdRequestMethod(r) == HTTP_UNKOWN) {
                char errStr[HTTP_MAX_BUFFER_SIZE]={0};
                _httpd_net_write(r->clientSock, HTTP_METHOD_ERROR, strlen(HTTP_METHOD_ERROR));
                _httpd_net_write(r->clientSock, cp, strlen(cp));
                snprintf(errStr, sizeof(errStr)-1, "ReqMethodInvalid:%s", cp);
                _httpd_writeErrorLog(server, r, LEVEL_ERROR, errStr);
                return HTTP_ERR_UNKOWN_METHOD;
            }

            /* Request URI: /sms/smsquest?phone=xxx */
            cp = cp2 + 1;
            while (*cp == ' ')
                cp++;
            cp2 = cp;
            while (*cp2 != ' ' && *cp2 != 0)
                cp2++;
            *cp2 = 0;
            strncpy(r->request.path, cp, sizeof(r->request.path)-1);
            r->request.path[sizeof(r->request.path) - 1] = 0;
            _httpd_sanitiseUrl(r->request.path);

            /* Request Version: HTTP/1.1 */
            cp = cp2 + 1;
            while (*cp == ' ')
                cp++;
            cp2 = cp;
            while (*cp2 != ' ' && *cp2 != 0)
                cp2++;
            *cp2 = 0;
            if(0==strcmp(HTTP_VERSION_10, cp) || 0==strcmp(HTTP_VERSION_11, cp))
                strncpy(r->request.version, cp, sizeof(r->request.version)-1);
            else
                strncpy(r->request.version, DEFAULT_HTTP_VERSION, sizeof(r->request.version)-1);
            r->request.version[sizeof(r->request.version)-1] = 0;
            continue;
        }

        /*
         ** Process the headers
         */
        if (inHeaders) {
            if (*buf == 0) {
                /*
                 ** End of headers.  Continue if there's
                 ** data to read
                 */
                break;
            }

            if (strncasecmp(buf, "Authorization: ", 15) == 0) {
                cp = strchr(buf, ':');
                if (cp) {
                    cp += 2;

                    if (strncmp(cp, "Basic ", 6) != 0) {
                        /* Unknown auth method */
                    } else {
                        char authBuf[HTTP_MAX_BUFFER_SIZE];

                        cp = strchr(cp, ' ') + 1;
                        _httpd_decode(cp, authBuf, HTTP_MAX_BUFFER_SIZE);
                        r->request.authLength = strlen(authBuf);
                        cp = strchr(authBuf, ':');
                        if (cp) {
                            *cp = 0;
                            strncpy(r->request.authPassword, cp + 1, sizeof(r->request.authPassword)-1);
                            r->request.authPassword[sizeof(r->request.authPassword) - 1] = 0;
                        }
                        strncpy(r->request.authUser, authBuf, sizeof(r->request.authUser)-1);
                        r->request.authUser[sizeof(r->request.authUser) - 1] = 0;
                    }
                }
                continue;
            }
            /* acv@acv.ca: Added decoding of host: if present. */
            if (strncasecmp(buf, "Host: ", 6) == 0) {
                cp = strchr(buf, ':');
                if (cp) {
                    cp += 2;
                    strncpy(r->request.host, cp, sizeof(r->request.host)-1);
                    r->request.host[sizeof(r->request.host) - 1] = 0;
                }
                continue;
            }
            /* coco@rhy.com: Added decoding of user-agent: if present. */
            if (strncasecmp(buf, "User-Agent: ", 12) == 0) {
                cp = strchr(buf, ':');
                if (cp) {
                    cp += 2;
                    strncpy(r->request.user_agent, cp, sizeof(r->request.user_agent)-1);
                    r->request.user_agent[sizeof(r->request.user_agent) - 1] = 0;
                }
                continue;
            }

            /* End modification */
            continue;
        }
    }

    /* Get nothing at all */
    if(0==count)
    {
        if(ret==0)
            return HTTP_ERR_CONN_TIMEOUT;
        else
            return HTTP_ERR_SOCKET_OR_READ;
    }

    /*
     ** Process any URL data
     */
    cp = strchr(r->request.path, '?');
    if (cp != NULL) {
        *cp++ = 0;
        strncpy(r->request.query, cp, sizeof(r->request.query)-1);
        r->request.query[sizeof(r->request.query) - 1] = 0;
        _httpd_storeData(r, cp);
    }

    return HTTP_RET_SUCCESS;
}

void httpdEndRequest(request* r)
{
    _httpd_freeVariables(r->variables);
    shutdown(r->clientSock, 2);
    close(r->clientSock);
    free(r);
}

void httpdFreeVariables(request* r)
{
    _httpd_freeVariables(r->variables);
}

void httpdDumpVariables(request* r)
{
    httpVar* curVar, *curVal;

    curVar = r->variables;
    while (curVar) {
        printf("Variable '%s'\n", curVar->name);
        curVal = curVar;
        while (curVal) {
            printf("\t= '%s'\n", curVal->value);
            curVal = curVal->nextValue;
        }
        curVar = curVar->nextVariable;
    }
}

void httpdSetFileBase(httpd* server, const char* path)
{
    strncpy(server->fileBasePath, path, HTTP_MAX_URL);
    server->fileBasePath[HTTP_MAX_URL - 1] = 0;
}

int httpdAddFileContent(httpd* server, char* dir, char* name, int indexFlag, int (*preload)(), char* path)
{
    httpDir* dirPtr;
    httpContent *newEntry;

    dirPtr = _httpd_findContentDir(server, dir, HTTP_TRUE);
    newEntry = malloc(sizeof(httpContent));
    if (newEntry == NULL)
        return (-1);
    bzero(newEntry, sizeof(httpContent));
    newEntry->name = strdup(name);
    newEntry->type = HTTP_FILE;
    newEntry->indexFlag = indexFlag;
    newEntry->preload = preload;
    newEntry->next = dirPtr->entries;
    dirPtr->entries = newEntry;
    if (*path == '/') {
        /* Absolute path */
        newEntry->path = strdup(path);
    } else {
        /* Path relative to base path */
        newEntry->path = malloc(strlen(server->fileBasePath) + strlen(path) + 2);
        snprintf(newEntry->path, HTTP_MAX_URL, "%s/%s", server->fileBasePath, path);
    }
    return (0);
}

int httpdAddWildcardContent(httpd* server, char* dir, int (*preload)(), char* path)
{
    httpDir* dirPtr;
    httpContent *newEntry;

    dirPtr = _httpd_findContentDir(server, dir, HTTP_TRUE);
    newEntry = malloc(sizeof(httpContent));
    if (newEntry == NULL)
        return (-1);
    bzero(newEntry, sizeof(httpContent));
    newEntry->name = NULL;
    newEntry->type = HTTP_WILDCARD;
    newEntry->indexFlag = HTTP_FALSE;
    newEntry->preload = preload;
    newEntry->next = dirPtr->entries;
    dirPtr->entries = newEntry;
    if (*path == '/') {
        /* Absolute path */
        newEntry->path = strdup(path);
    } else {
        /* Path relative to base path */
        newEntry->path = malloc(strlen(server->fileBasePath) + strlen(path) + 2);
        snprintf(newEntry->path, HTTP_MAX_URL, "%s/%s", server->fileBasePath, path);
    }
    return (0);
}

int httpdLoadFile2Buff(httpd* server, const char* path, char** ppBuffer)
{
    struct stat stat_info;
    int fd;
    int read_len;
    char errBuf[HTTP_MAX_BUFFER_SIZE]={0};
    
    fd = open(path, O_RDONLY);
    if(fd < 0)
    {
        snprintf(errBuf, sizeof(errBuf)-1, "Failed to open file: %s, errReason:%s", path, strerror(errno));
        _httpd_writeErrorLog(server, NULL, LEVEL_ERROR, errBuf);
        return HTTP_ERR_OPEN_FILE;
    }
    
    if(fstat(fd, &stat_info) == -1) 
    {
        snprintf(errBuf, sizeof(errBuf)-1, "Failed to fstat file: %s, errReason:%s", path, strerror(errno));
        _httpd_writeErrorLog(server, NULL, LEVEL_ERROR, errBuf);
        close(fd);
        return HTTP_ERR_STAT_FILE;
    }
    
    if(stat_info.st_size >= HTTP_MAX_SEND_FILE_SIZE-1)
    {
        snprintf(errBuf, sizeof(errBuf)-1, "Failed to load file: %s, size:%u too large", 
                               path, (uint32_t)stat_info.st_size);
        _httpd_writeErrorLog(server, NULL, LEVEL_ERROR, errBuf);
        close(fd);
        return HTTP_ERR_FILE_SIZE;
    }
    
    // Cast from long to unsigned int
    *ppBuffer = (char* )malloc((size_t)stat_info.st_size + 1);
    if(*ppBuffer)
    {
        memset(*ppBuffer, 0, (size_t)stat_info.st_size + 1); //to make sure the last byte is 0;
        read_len = read(fd, *ppBuffer, (size_t)stat_info.st_size);
        if(read_len<=0)
        {
            free(*ppBuffer);
            *ppBuffer=NULL;
        }
        close(fd);
        return read_len;
    }
    close(fd);
    return HTTP_ERR_MEM_ALLOC;
}

void _httpdDumpDirContent(char* ParentDirName, httpDir* curDir)
{
    char Buff[HTTP_MAX_PATH_LEN] = {0};
    struct _httpd_content *pEntry;
    
    if(curDir)
        snprintf(Buff, sizeof(Buff)-1, "%s/%s", ParentDirName, curDir->name);
    else
        return;
    for(pEntry=curDir->entries; pEntry; pEntry=pEntry->next)
    {
        printf("%s/%s:\n    type[%d]indexFlag[%d]func[%p]data[%s]path[%s]preload[%p]\n", Buff, pEntry->name, 
                pEntry->type, pEntry->indexFlag, pEntry->function, pEntry->data, pEntry->path, pEntry->preload);
    }
}

void _httpdDumpSubDir(char* ParentDirName, httpDir* curDir)
{
    char Buff[HTTP_MAX_PATH_LEN] = {0};

    _httpdDumpDirContent(ParentDirName, curDir);
    for(; curDir; curDir=curDir->next)
    {
        snprintf(Buff, sizeof(Buff)-1, "%s/%s", ParentDirName, curDir->name);
        _httpdDumpSubDir(Buff, curDir->children);
    }
}

void httpdDumpContent(httpd* server)
{
    printf("Dump Content of web server %s:\n", server->name);
    return _httpdDumpSubDir("", server->content);
}


int httpdAddCContent(httpd* server, char* dir, char* name, int indexFlag, int (*preload)(), void (*function)())
{
    httpDir* dirPtr;
    httpContent *newEntry;

    dirPtr = _httpd_findContentDir(server, dir, HTTP_TRUE);
    newEntry = malloc(sizeof(httpContent));
    if (newEntry == NULL)
        return (-1);
    bzero(newEntry, sizeof(httpContent));
    newEntry->name = strdup(name);
    newEntry->type = HTTP_C_FUNCT;
    newEntry->indexFlag = indexFlag;
    newEntry->function = function;
    newEntry->preload = preload;
    newEntry->next = dirPtr->entries;
    dirPtr->entries = newEntry;
    return (0);
}

int httpdAddCWildcardContent(httpd* server, char* dir, int (*preload)(), void (*function)())
{
    httpDir* dirPtr;
    httpContent *newEntry;

    dirPtr = _httpd_findContentDir(server, dir, HTTP_TRUE);
    newEntry = malloc(sizeof(httpContent));
    if (newEntry == NULL)
        return (-1);
    bzero(newEntry, sizeof(httpContent));
    newEntry->name = NULL;
    newEntry->type = HTTP_C_WILDCARD;
    newEntry->indexFlag = HTTP_FALSE;
    newEntry->function = function;
    newEntry->preload = preload;
    newEntry->next = dirPtr->entries;
    dirPtr->entries = newEntry;
    return (0);
}

int httpdAddStaticContent(httpd* server, char* dir, char* name, int indexFlag, int (*preload)(), char* data)
{
    httpDir* dirPtr;
    httpContent *newEntry;

    dirPtr = _httpd_findContentDir(server, dir, HTTP_TRUE);
    newEntry = malloc(sizeof(httpContent));
    if (newEntry == NULL)
        return (-1);
    bzero(newEntry, sizeof(httpContent));
    newEntry->name = strdup(name);
    newEntry->type = HTTP_STATIC;
    newEntry->indexFlag = indexFlag;
    newEntry->data = data;
    newEntry->preload = preload;
    newEntry->next = dirPtr->entries;
    dirPtr->entries = newEntry;
    return (0);
}

void httpdSendHeaders(request* r)
{
    _httpd_sendHeaders(r, 0, 0);
}

void httpdSetResponse(request *r, const char* msg)
{
    strncpy(r->response.response, msg, HTTP_MAX_URL - 1);
    r->response.response[HTTP_MAX_URL - 1] = 0;
}

void httpdSetContentType(request* r, const char* type)
{
    strncpy(r->response.contentType, type, HTTP_MAX_URL - 1);
    r->response.contentType[HTTP_MAX_URL - 1] = 0;
}

void httpdAddHeader(request* r, const char* msg)
{
    int size;
    size = HTTP_MAX_HEADERS - 2 - strlen(r->response.headers);
    if (size > 0) {
        strncat(r->response.headers, msg, size);
        if (r->response.headers[strlen(r->response.headers) - 1] != '\n')
            strcat(r->response.headers, "\n");
    }
}

void httpdSetCookie(request* r, const char* name, const char* value)
{
    char buf[HTTP_MAX_URL]={0};

    snprintf(buf, HTTP_MAX_URL-1, "Set-Cookie: %s=%s; path=/;", name, value);
    httpdAddHeader(r, buf);
}

void httpdOutput(request* r, const char* msg)
{
    const char* src;
    char* buf = malloc(HTTP_MAX_LEN);
    char* varName = malloc(HTTP_MAX_LEN);
    char* dest;
    int count;

    if(NULL==buf || NULL==varName) 
    {
        goto Bailout;
    }

    src = msg;
    dest = buf;
    count = 0;
    memset(buf, 0, HTTP_MAX_LEN);
    while (*src && count < HTTP_MAX_LEN) {
        if (*src == '$') {
            const char* tmp;
            char* cp;
            int count2;
            httpVar* curVar;

            tmp = src + 1;
            cp = varName;
            count2 = 0;
            while (*tmp && (isalnum((unsigned char)*tmp) || *tmp == '_') && count2 < HTTP_MAX_LEN-1) {
                *cp++ = *tmp++;
                count2++;
            }
            *cp = 0;
            curVar = httpdGetVariableByName(r, varName);
            if (curVar && ((count + strlen(curVar->value)) < HTTP_MAX_LEN)) {
                strcpy(dest, curVar->value);
                dest = dest + strlen(dest);
                count += strlen(dest);
                src = src + strlen(varName) + 1;
                continue;
            } else {
                *dest++ = *src++;
                count++;
                continue;
            }
        }
        *dest++ = *src++;
        count++;
    }
    *dest = 0;
    
Bailout:
    r->response.responseLength += strlen(buf);
    if (r->response.headersSent == 0)
        httpdSendHeaders(r);
    _httpd_net_write(r->clientSock, buf, strlen(buf));
    if(buf)     free(buf);
    if(varName) free(varName);
}

#ifdef HAVE_STDARG_H
void httpdPrintf(request* r, const char* fmt, ...)
{
#else
void httpdPrintf(va_alist)
va_dcl
{
    request *r;;
    const char* fmt;
#endif
    va_list args;
    char buf[HTTP_READ_BUF_LEN];

#ifdef HAVE_STDARG_H
    va_start(args, fmt);
#else
    va_start(args);
    r = (request *) va_arg(args, request *);
    fmt = (char* )va_arg(args, char* );
#endif
    if (r->response.headersSent == 0)
        httpdSendHeaders(r);
    vsnprintf(buf, HTTP_READ_BUF_LEN, fmt, args);
    va_end(args); /* Works with both stdargs.h and varargs.h */
    r->response.responseLength += strlen(buf);
    _httpd_net_write(r->clientSock, buf, strlen(buf));
}

void httpdProcessRequest(httpd*  server, request* r)
{
    char dirName[HTTP_MAX_URL], entryName[HTTP_MAX_URL], *cp;
    httpDir* dir;
    httpContent *entry;

    r->response.responseLength = 0;
    strncpy(dirName, httpdRequestPath(r), HTTP_MAX_URL);
    dirName[HTTP_MAX_URL - 1] = 0;
    cp = strrchr(dirName, '/');
    if (cp == NULL) {
        //printf("Invalid request path '%s'\n", dirName);
        return;
    }
    strncpy(entryName, cp + 1, HTTP_MAX_URL);
    entryName[HTTP_MAX_URL - 1] = 0;
    if (cp != dirName)
        *cp = 0;
    else
        *(cp + 1) = 0;
    dir = _httpd_findContentDir(server, dirName, HTTP_FALSE);
    if (dir == NULL) {
        _httpd_send404(server, r);
        _httpd_writeAccessLog(server, r);
        return;
    }
    entry = _httpd_findContentEntry(r, dir, entryName);
    if (entry == NULL) {
        _httpd_send404(server, r);
        _httpd_writeAccessLog(server, r);
        return;
    }
    if (entry->preload) {
        if ((entry->preload) (server) < 0) {
            _httpd_writeAccessLog(server, r);
            return;
        }
    }
    //printf("entry->type %d\n", entry->type);
    switch (entry->type) {
    case HTTP_C_FUNCT:
    case HTTP_C_WILDCARD:
        (entry->function) (server, r);
        break;

    case HTTP_STATIC:
        _httpd_sendStatic(server, r, entry->data);
        break;

    case HTTP_FILE:
        httpdSendFile(server, r, entry->path);
        break;

    case HTTP_WILDCARD:
        if (_httpd_sendDirectoryEntry(server, r, entry, entryName) < 0) {
            _httpd_send404(server, r);
        }
        break;
    }
    _httpd_writeAccessLog(server, r);
}

void httpdSetAccessLog(httpd* server, FILE* fp)
{
    if(server)
    {
        server->accessLog = fp;
    }
}

void httpdSetErrorLog(httpd* server, FILE* fp)
{
    if(server)
    {
        server->errorLog = fp;
    }
}

int httpdAuthenticate(request* r, const char* realm)
{
    char buffer[HTTP_MAX_BUFFER_SIZE]={0};

    if (r->request.authLength == 0) {
        httpdSetResponse(r, "401 Please Authenticate");
        snprintf(buffer, sizeof(buffer)-1, "WWW-Authenticate: Basic realm=\"%s\"\n", realm);
        httpdAddHeader(r, buffer);
        httpdOutput(r, "\n");
        return (0);
    }
    return (1);
}

int httpdSetErrorFunction(httpd*  server, int error, void (*function)())
{
    char errBuf[HTTP_MAX_BUFFER_SIZE]={0};

    switch (error) {
    case 304:
        server->errorFunction304 = function;
        break;
    case 403:
        server->errorFunction403 = function;
        break;
    case 404:
        server->errorFunction404 = function;
        break;
    default:
        snprintf(errBuf, sizeof(errBuf)-1, "Invalid error code (%d) for custom callback", error);
        _httpd_writeErrorLog(server, NULL, LEVEL_ERROR, errBuf);
        return (-1);
        break;
    }
    return (0);
}

void httpdSendFile(httpd*  server, request* r, const char* path)
{
    char* suffix;
    struct stat sbuf;

    suffix = strrchr(path, '.');
    if (suffix != NULL) {
        if (strcasecmp(suffix, ".gif") == 0)
            strcpy(r->response.contentType, "image/gif");
        if (strcasecmp(suffix, ".jpg") == 0)
            strcpy(r->response.contentType, "image/jpeg");
        if (strcasecmp(suffix, ".xbm") == 0)
            strcpy(r->response.contentType, "image/xbm");
        if (strcasecmp(suffix, ".png") == 0)
            strcpy(r->response.contentType, "image/png");
        if (strcasecmp(suffix, ".ico") == 0)
            strcpy(r->response.contentType, "image/ico");
        if (strcasecmp(suffix, ".css") == 0)
            strcpy(r->response.contentType, "text/css");
    }
    if (stat(path, &sbuf) < 0)
    {
        _httpd_send404(server, r);
        return;
    }
    if (_httpd_checkLastModified(r, sbuf.st_mtime) == 0) 
    {
        _httpd_send304(server, r);
    }
    else
    {
        _httpd_sendHeaders(r, sbuf.st_size, sbuf.st_mtime);
        _httpd_catFile(server, r, path);
    }
}

void httpdForceAuthenticate(request* r, const char* realm)
{
    char buffer[HTTP_MAX_BUFFER_SIZE]={0};

    httpdSetResponse(r, "401 Please Authenticate");
    snprintf(buffer, sizeof(buffer)-1, "WWW-Authenticate: Basic realm=\"%s\"\n", realm);
    httpdAddHeader(r, buffer);
    httpdOutput(r, "\n");
}

