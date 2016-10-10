/*
** Copyright (c) 2002  Hughes Technologies Pty Ltd.  All rights
** reserved.
**
** Terms under which this software may be used or copied are
** provided in the  specific license associated with this product.
**
** hUghes Technologies disclaims all warranties with regard to this
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

/*
**  libhttpd Header File
*/

/***********************************************************************
** Standard header preamble.  Ensure singular inclusion, setup for
** function prototypes and c++ inclusion
*/

#ifndef LIB_HTTPD_H

#define LIB_HTTPD_H 1

#include <sys/time.h>

#if !defined(__ANSI_PROTO)
#if defined(_WIN32) || defined(__STDC__) || defined(__cplusplus)
#define __ANSI_PROTO(x)       x
#else
#define __ANSI_PROTO(x)       ()
#endif
#endif

#ifndef u_int
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
** Macro Definitions
*/
//#define SEMU_TEST 1
#define HTTP_MAX_PATH_LEN         256
#define HTTP_WEB_NAME_LEN         20
#define HTTP_PORT                 80
#define HTTP_MAX_SEND_FILE_SIZE   100*1024
#define HTTP_MAX_LEN              HTTP_MAX_SEND_FILE_SIZE
#define HTTP_MAX_BUFFER_SIZE      256
#define HTTP_METHOD_MAX_LEN       20
#define HTTP_MAX_URL              1024
#define HTTP_MAX_VERSION_LEN      10
#define HTTP_MAX_HEADERS          1024
#define HTTP_MAX_AUTH             128
#define HTTP_IP_ADDR_LEN          17
#define HTTP_TIME_STRING_LEN      50   /* used to be 40 */
#define HTTP_MAX_HOST_LEN         256
#define HTTP_MAX_USER_AGENT       256
#define HTTP_READ_BUF_LEN         4096
#define HTTP_ANY_ADDR             NULL
#define HTTP_MAX_SELECT_SECONDS   10

typedef enum{
    HTTP_UNKOWN = 0,
    HTTP_GET    = 1,
    HTTP_HEAD   = 2,
    HTTP_PUT    = 3,
    HTTP_DELETE = 4,
    HTTP_POST   = 5,
    HTTP_OPTIONS= 6,
    HTTP_TRACE  = 7,
    HTTP_CONNECT= 8,
    HTTP_NOTIFY = 9,
    HTTP_METHOD_MAX
}t_httpmethod;

#define	HTTP_TRUE           1
#define HTTP_FALSE          0

#define HTTP_FILE           1
#define HTTP_C_FUNCT        2
#define HTTP_EMBER_FUNCT    3
#define HTTP_STATIC         4
#define HTTP_WILDCARD       5
#define HTTP_C_WILDCARD     6

#define HTTP_METHOD_ERROR "\n<B>ERROR : Method Not Implemented</B>\n\n"

#define httpdRequestMethod(s)          s->request.method
#define httpdRequestHost(s)            s->request.host
#define httpdRequestPath(s)            s->request.path
#define httpdRequestVersion(s)         s->request.version
#define httpdRequestContentType(s)     s->request.contentType
#define httpdRequestContentLength(s)   s->request.contentLength

#define HTTP_ACL_PERMIT     1
#define HTTP_ACL_DENY       2

extern char LIBHTTPD_VERSION[];
extern char LIBHTTPD_VENDOR[];

#define HTTP_RET_BASE 0
#define HTTP_RET_SUCCESS HTTP_RET_BASE                    /* Success:0 */

#define HTTP_RET_ERRBASE           HTTP_RET_BASE-1000     /* ErrorBase:-1000 */
#define HTTP_ERR_OPEN_FILE         HTTP_RET_ERRBASE-0     /* -1000 */
#define HTTP_ERR_STAT_FILE         HTTP_RET_ERRBASE-1     /* -1001 */
#define HTTP_ERR_FILE_SIZE         HTTP_RET_ERRBASE-2     /* -1002 */
#define HTTP_ERR_MEM_ALLOC         HTTP_RET_ERRBASE-3     /* -1003 */
#define HTTP_ERR_CONN_TIMEOUT      HTTP_RET_ERRBASE-4     /* -1004 */
#define HTTP_ERR_UNKOWN_METHOD     HTTP_RET_ERRBASE-5     /* -1005 */
#define HTTP_ERR_SOCKET_OR_READ    HTTP_RET_ERRBASE-6     /* -1006 */

#ifndef HTTP_VERSION_11
#define HTTP_VERSION_11 "HTTP/1.1"
#endif
#ifndef HTTP_VERSION_10
#define HTTP_VERSION_10 "HTTP/1.0"
#endif
#ifndef DEFAULT_HTTP_VERSION
#define DEFAULT_HTTP_VERSION HTTP_VERSION_11
#endif

/***********************************************************************
** Type Definitions
*/

    typedef struct {
        t_httpmethod method;
        int contentLength;
        int authLength;
        char path[HTTP_MAX_URL];
        char query[HTTP_MAX_URL];
        char version[HTTP_MAX_VERSION_LEN];
        char host[HTTP_MAX_HOST_LEN];    /* acv@acv.ca: Added decoding of host: header if present. */
        char user_agent[HTTP_MAX_USER_AGENT];
        char ifModified[HTTP_TIME_STRING_LEN];
        char authUser[HTTP_MAX_AUTH];
        char authPassword[HTTP_MAX_AUTH];
    } httpReq;

    typedef struct _httpd_var {
        char* name;
        char* value;
        struct _httpd_var* nextValue;
        struct _httpd_var* nextVariable;
    } httpVar;

    typedef struct _httpd_content {
        char *name;
        int type, indexFlag;
        void (*function) ();
        char *data, *path;
        int (*preload) ();
        struct _httpd_content *next;
    } httpContent;

    typedef struct {
        int responseLength;
        httpContent *content;
        char headersSent;
        char headers[HTTP_MAX_HEADERS];
        char response[HTTP_MAX_URL];
        char contentType[HTTP_MAX_URL];
    } httpRes;

    typedef struct _httpd_dir {
        char name[HTTP_MAX_BUFFER_SIZE];
        struct _httpd_dir *children, *next;
        struct _httpd_content *entries;
    } httpDir;

    typedef struct ip_acl_s {
        int addr;
        char len, action;
        struct ip_acl_s *next;
    } httpAcl;

    typedef struct {
        char name[HTTP_WEB_NAME_LEN];
        int port;
        int serverSock;
        int startTime;
        int lastError;
        char fileBasePath[HTTP_MAX_URL];
        char host[HTTP_IP_ADDR_LEN];
        httpDir *content;
        httpAcl *defaultAcl;
        FILE *accessLog;
        FILE *errorLog;
        void (*errorFunction304) ();
        void (*errorFunction403) ();
        void (*errorFunction404) ();
    } httpd;

    typedef struct {
        int clientSock;
        int readBufRemain;
        httpReq request;
        httpRes response;
        httpVar *variables;
        char *readBufPtr;
        char readBuf[HTTP_READ_BUF_LEN + 1];
        char clientAddr[HTTP_IP_ADDR_LEN];
    } request;

/***********************************************************************
** Function Prototypes
*/
    int httpdLoadFile2Buff __ANSI_PROTO((httpd* server, const char *path, char** ppBuffer));
    void httpdDumpContent __ANSI_PROTO((httpd *server));
    int httpdAddCContent __ANSI_PROTO((httpd *, char *, char *, int, int (*)(), void (*)()));
    int httpdAddFileContent __ANSI_PROTO((httpd *, char *, char *, int, int (*)(), char *));
    int httpdAddStaticContent __ANSI_PROTO((httpd *, char *, char *, int, int (*)(), char *));
    int httpdAddWildcardContent __ANSI_PROTO((httpd *, char *, int (*)(), char *));
    int httpdAddCWildcardContent __ANSI_PROTO((httpd *, char *, int (*)(), void (*)()));
    int httpdAddVariable __ANSI_PROTO((request *, const char *, const char *));
    int httpdSetVariableValue __ANSI_PROTO((request *, const char *, const char *));
    request *httpdGetConnection __ANSI_PROTO((httpd *, struct timeval *));
    int httpdReadRequest __ANSI_PROTO((httpd *, request *));
    int httpdCheckAcl __ANSI_PROTO((httpd *, request *, httpAcl *));
    int httpdAuthenticate __ANSI_PROTO((request *, const char *));
    void httpdForceAuthenticate __ANSI_PROTO((request *, const char *));
    int httpdSetErrorFunction __ANSI_PROTO((httpd *, int, void (*)()));
    char *httpdUrlEncode __ANSI_PROTO((const char *));
    char* httpdMethod2Name __ANSI_PROTO((t_httpmethod , char* , size_t));
    void httpdAddHeader __ANSI_PROTO((request *, const char *));
    void httpdSetContentType __ANSI_PROTO((request *, const char *));
    void httpdSetResponse __ANSI_PROTO((request *, const char *));
    void httpdEndRequest __ANSI_PROTO((request *));

    httpd *httpdCreate __ANSI_PROTO((char* , int, char*));
    void httpdFreeVariables __ANSI_PROTO((request *));
    void httpdDumpVariables __ANSI_PROTO((request *));
    void httpdOutput __ANSI_PROTO((request *, const char *));
    void httpdPrintf __ANSI_PROTO((request *, const char *, ...));
    void httpdProcessRequest __ANSI_PROTO((httpd *, request *));
    void httpdSendHeaders __ANSI_PROTO((request *));
    void httpdSendFile __ANSI_PROTO((httpd *, request *, const char *));
    void httpdSetFileBase __ANSI_PROTO((httpd *, const char *));
    void httpdSetCookie __ANSI_PROTO((request *, const char *, const char *));

    void httpdSetErrorLog __ANSI_PROTO((httpd *, FILE *));
    void httpdSetAccessLog __ANSI_PROTO((httpd *, FILE *));
    void httpdSetDefaultAcl __ANSI_PROTO((httpd *, httpAcl *));

    httpVar *httpdGetVariableByName __ANSI_PROTO((request *, const char *));
    httpVar *httpdGetVariableByPrefix __ANSI_PROTO((request *, const char *));
    httpVar *httpdGetVariableByPrefixedName __ANSI_PROTO((request *, const char *, const char *));
    httpVar *httpdGetNextVariableByPrefix __ANSI_PROTO((httpVar *, const char *));

    httpAcl *httpdAddAcl __ANSI_PROTO((httpd *, httpAcl *, char *, int));

/***********************************************************************
** Standard header file footer.  
*/

#ifdef __cplusplus
}
#endif                          /* __cplusplus */
#endif                          /* file inclusion */
