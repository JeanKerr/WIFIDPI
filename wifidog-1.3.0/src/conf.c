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
/** @file conf.c
  @brief Config file parsing
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire, Technologies Coeus inc.
 */

#include "common.h"

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "http.h"
#include "auth.h"
#include "firewall.h"
#include "config.h"

#include "util.h"

/** @internal
 * Holds the current configuration of the gateway */
static T_CONFIG config;
static char portal_version[PORTAL_VERSTRING_LEN]="0.0";

/**
 * Mutex for the configuration file, used by the auth_servers related
 * functions. */
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t auth_srv_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t auth_agt_mutex = PTHREAD_MUTEX_INITIALIZER;


/** @internal
 * A flag.  If set to 1, there are missing or empty mandatory parameters in the config
 */
static int missing_parms=0;

/** @internal
 The different configuration options */
typedef enum {
    oBadOption,
    oDaemon,
    oDebugLevel,
    oExternalInterface,
    oExternalAddress,
    oExternalPort,
    oGatewayID,
    oGatewayInterface,
    oGatewayAddress,
    oGatewayPort,
    oDeltaTraffic,
    oAuthServer,
    oAuthAgent,
    oAuthServHostname,
    oAuthServHostip,
    oAuthServSSLAvailable,
    oAuthServSSLPort,
    oAuthAgentTCPPort,
    oAuthServHTTPPort,
    oAuthServActivePath,
    oAuthServPassivePath,
    oAuthServSeperator,
    oAuthServCheckScriptPathFragment,
    oAuthServSmsScriptPathFragment,
    oAuthServLoginScriptPathFragment,
    oAuthServPassScriptPathFragment,
    oAuthServOfflineScriptPathFragment,
    oAuthServPortalScriptPathFragment,
    oUpdatePortalPathFragment,
    oDLoadPortalPathFragment,
    oAuthServMsgScriptPathFragment,
    oAuthServPingScriptPathFragment,
    oAuthServAuthScriptPathFragment,
    oHTTPDMaxConn,
    oHTTPDName,
    oHTTPDRealm,
    oHTTPDUsername,
    oHTTPDPassword,
    oMaxClientNum,
    oClientTimeout,
    oCheckInterval,
    oWdctlSocket,
    oSyslogFacility,
    oFirewallRule,
    oFirewallRuleSet,
    oTrustedMACList,
    oPopularServers,
    oHtmlMessageFile,
    oProxyPort,
    oSSLPeerVerification,
    oSSLCertPath,
    oSSLAllowedCipherList,
    oSSLUseSNI,
    oHttpAccessLogFile,
    oHttpErrorLogFile,
    oHttpVersion,
    oPlaceCode,
    oPortalCode,
    oCompany,
    oCompanyId,
    oSsid,
    oLessee_id,
    oPortalSavePath,
    oFaviconIcoPath,
    oSmsFlag,
    oLocalAuthFlag,
    oSemuFlag,
    oSemuPortalIp,
    oDpiFlag,
    oDpiBPF,
    oDpiLogFile
} OpCodes;

/** @internal
 The config file keywords for the different configuration options */
typedef struct _KEYWORDs{
    const char *name;
    OpCodes opcode;
}T_KEYWORD;

static const T_KEYWORD keywords[] = {
    {
    "deltatraffic", oDeltaTraffic}, {
    "daemon", oDaemon}, {
    "debuglevel", oDebugLevel}, {
    "externalinterface", oExternalInterface}, {
    "externaladdress", oExternalAddress}, {
    "externalport", oExternalPort}, {
    "gatewayid", oGatewayID}, {
    "gatewayinterface", oGatewayInterface}, {
    "gatewayaddress", oGatewayAddress}, {
    "gatewayport", oGatewayPort}, {
    "authserver", oAuthServer}, {
    "authagent", oAuthAgent}, {
    "httpdmaxconn", oHTTPDMaxConn}, {
    "httpdname", oHTTPDName}, {
    "httpdrealm", oHTTPDRealm}, {
    "httpdusername", oHTTPDUsername}, {
    "httpdpassword", oHTTPDPassword}, {
    "maxclientnum", oMaxClientNum}, {
    "clienttimeout", oClientTimeout}, {
    "checkinterval", oCheckInterval}, {
    "syslogfacility", oSyslogFacility}, {
    "wdctlsocket", oWdctlSocket}, {
    "hostname", oAuthServHostname}, {
    "hostip", oAuthServHostip}, {
    "sslavailable", oAuthServSSLAvailable}, {
    "sslport", oAuthServSSLPort}, {
    "tcpport", oAuthAgentTCPPort}, {
    "httpport", oAuthServHTTPPort}, {
    "activepath", oAuthServActivePath}, {
    "passivepath", oAuthServPassivePath}, {
    "seperator", oAuthServSeperator}, {
    "checkscriptpathfragment", oAuthServCheckScriptPathFragment}, {
    "smsscriptpathfragment", oAuthServSmsScriptPathFragment}, {
    "loginscriptpathfragment", oAuthServLoginScriptPathFragment}, {
    "passscriptpathfragment", oAuthServPassScriptPathFragment}, {
    "offlinescriptpathfragment", oAuthServOfflineScriptPathFragment}, {
    "portalscriptpathfragment", oAuthServPortalScriptPathFragment}, {
    "updateportalpathfragment", oUpdatePortalPathFragment}, {
    "msgscriptpathfragment", oAuthServMsgScriptPathFragment}, {
    "pingscriptpathfragment", oAuthServPingScriptPathFragment}, {
    "authscriptpathfragment", oAuthServAuthScriptPathFragment}, {
    "firewallruleset", oFirewallRuleSet}, {
    "firewallrule", oFirewallRule}, {
    "trustedmaclist", oTrustedMACList}, {
    "popularservers", oPopularServers}, {
    "htmlmessagefile", oHtmlMessageFile}, {
    "proxyport", oProxyPort}, {
    "sslpeerverification", oSSLPeerVerification}, {
    "sslcertpath", oSSLCertPath}, {
    "sslallowedcipherlist", oSSLAllowedCipherList}, {
    "sslusesni", oSSLUseSNI}, {
    /* coco begin */
    "httpaccesslogfile", oHttpAccessLogFile}, {
    "httperrorlogfile", oHttpErrorLogFile}, {
    "httpversion", oHttpVersion}, {
    "placecode", oPlaceCode}, {
    "portalcode", oPortalCode}, {
    "company", oCompany}, {
    "companyid", oCompanyId}, {
    "ssid", oSsid}, {
    "lessee_id", oLessee_id}, {
    "portalsavepath", oPortalSavePath}, {
    "faviconicopath", oFaviconIcoPath}, {
    "smsflag", oSmsFlag}, {
    "localauthflag", oLocalAuthFlag}, {
    "semuflag", oSemuFlag}, {
    "semuportalip", oSemuPortalIp}, {
    "dpiflag", oDpiFlag}, {
    "dpibpf", oDpiBPF}, {
    "dpilogfile", oDpiLogFile}, {

    
    /* coco end */
    NULL, oBadOption},};

static void config_notnull(const void *, const char *);
static int parse_boolean_value(char *);
static void parse_auth_server(FILE *, const char *, int *);
static int _parse_firewall_rule(const char *, char *);
static void parse_firewall_ruleset(const char *, FILE *, const char *, int *);
static void parse_trusted_mac_list(const char *);
static void parse_popular_servers(const char *);
static void validate_portal_version(void);
static void validate_popular_servers(void);
static void add_popular_server(const char *);

static OpCodes config_parse_token(const char *, const char *, int);

/** Accessor for the current gateway configuration
@return:  A pointer to the current config.  The pointer isn't opaque, but should be treated as READ-ONLY
 */
T_CONFIG* config_get_config(void)
{
    return &config;
}


void config_set_tcpsock(int sock)
{
#if USE_TCP_SOCK
    config.tcp_sock = sock;
#endif
}

char* get_portal_version_string(void)
{
    return portal_version;
}

char* set_portal_version_string(char* newVersion)
{
    debug(LOG_INFO, "set_portal_version_string newVersion:%s", newVersion);
    strncpy(portal_version, newVersion, PORTAL_VERSTRING_LEN-1);
    portal_version[PORTAL_VERSTRING_LEN-1]=0;
    return portal_version;
}

extern int RunRhyDpi;
void config_set_dpi(int start)
{
    RunRhyDpi = start;
    if(!config.dpi_flag)
    {
        debug(LOG_NOTICE, "Dpi subswitch set to %d but won't effect while dpi feature is stopped", start);
    }
}


/** Sets the default config parameters and initialises the configuration system */
void config_init(void)
{
    debug(LOG_DEBUG, "Setting default config parameters");
    memset(&config, 0, sizeof(config));
    strncpy(config.configfile, DEFAULT_CONFIGFILE, sizeof(config.configfile)-1);
    strncpy(config.htmlmsgfile, DEFAULT_HTMLMSGFILE, sizeof(config.htmlmsgfile)-1);  
    strncpy(config.wdctl_sock, DEFAULT_WDCTL_SOCK, sizeof(config.wdctl_sock)-1);
    strncpy(config.internal_sock, DEFAULT_INTERNAL_SOCK, sizeof(config.internal_sock)-1);
    strncpy(config.ssl_certs, DEFAULT_AUTHSERVSSLCERTPATH, sizeof(config.ssl_certs)-1);
    strncpy(config.http_accesslog_file, DEFAULT_HTTP_ACCESSLOG_FILENAME, sizeof(config.http_accesslog_file)-1);
    strncpy(config.http_errorlog_file, DEFAULT_HTTP_ERRORLOG_FILENAME, sizeof(config.http_errorlog_file)-1);
    strncpy(config.http_version, DEFAULT_HTTP_VERSION_CONF, sizeof(config.http_version)-1);
    strncpy(config.place_code, DEFAULT_PLACECODE, sizeof(config.place_code)-1);
    strncpy(config.portal_code, DEFAULT_PORTALCODE, sizeof(config.portal_code)-1);
    strncpy(config.company, DEFAULT_COMPANY, sizeof(config.company)-1);
    strncpy(config.ssid, DEFAULT_SSID, sizeof(config.ssid)-1);
    strncpy(config.lessee_id, DEFAULT_LESSEE_ID, sizeof(config.lessee_id)-1);
    strncpy(config.portal_save_path, DEFAULT_PORTAL_SAVE_PATH, sizeof(config.portal_save_path)-1);
    strncpy(config.favacon_ico_path, DEFAULT_FAVICONICO_PATH, sizeof(config.favacon_ico_path)-1);
    strncpy(config.arp_table_path, DEFAULT_ARPTABLE, sizeof(config.arp_table_path)-1);
    strncpy(config.httpdrealm, DEFAULT_HTTPDNAME, sizeof(config.httpdrealm)-1);
    strncpy(config.httpdusername, DEFAULT_HTTPDUSRNAME, sizeof(config.httpdusername)-1);
    strncpy(config.httpdpassword, DEFAULT_HTTPDPASSWORD, sizeof(config.httpdpassword)-1);
    strncpy(config.version, LIBHTTPD_VERSION, sizeof(config.version)-1);
    strncpy(config.dpi_bpf, DEFAULT_DPI_BPFFILTER, sizeof(config.dpi_bpf)-1);

    
    strncpy(config.auth_servers.name, AUTH_SVR_NAME, sizeof(config.auth_servers.name)-1);
    strncpy(config.auth_agents.name,  AUTH_AGT_NAME, sizeof(config.auth_agents.name) -1);
    config.net_conn.net_status = E_NET_CONN_INIT;
    
    config.company_id = DEFAULT_COMPANYID;    
    config.ssl_verify = DEFAULT_AUTHSERVSSLPEERVER;
    config.ssl_use_sni = DEFAULT_AUTHSERVSSLSNI;
#if USE_TCP_SOCK
    config.tcp_sock = -1;
#endif
    config.deltatraffic = DEFAULT_DELTATRAFFIC;
    config.sms_flag = 0;
    config.local_auth_flag = 0;
    config.semu_flag = 0;
    config.dpi_flag = 0;    /* shutdown dpi defaultly */
    /* coco add */
    config.httpdmaxconn = DEFAULT_HTTPDMAXCONN;
    config.external_web_port = DEFAULT_EXTERNALWEBPORT;
    config.gw_port = DEFAULT_GATEWAYPORT;
    
    config.max_client_num= DEFAULT_CLIENTMAXNUM;
    config.clienttimeout = DEFAULT_CLIENTTIMEOUT;
    config.checkinterval = DEFAULT_CHECKINTERVAL;
    config.daemon = -1;
    config.proxy_port = 0;

    debugconf.log_stderr = 1;
    debugconf.debuglevel = DEFAULT_DEBUGLEVEL;
    debugconf.syslog_facility = DEFAULT_SYSLOG_FACILITY;
    debugconf.log_syslog = DEFAULT_LOG_SYSLOG;
}

/**
 * If the command-line didn't provide a config, use the default.
 */
void config_init_override(void)
{
    if (config.daemon == -1) {
        config.daemon = DEFAULT_DAEMON;
        if (config.daemon > 0) {
            debugconf.log_stderr = 0;
        }
    }
}

/** @internal
Parses a single token from the config file
*/
static OpCodes config_parse_token(const char* cp, const char* filename, int linenum)
{
    int i;

    for (i = 0; keywords[i].name; i++)
        if (strcasecmp(cp, keywords[i].name) == 0)
            return keywords[i].opcode;

    debug(LOG_ERR, "%s: line %d: Bad configuration option: %s", filename, linenum, cp);
    return oBadOption;
}

/** @internal
Parses auth server information
*/
static void parse_auth_server2(FILE* file, const char* filename, int* linenum, t_auth_serv_mgmt_t* mgmt)
{
    char* hostname = NULL;
    char* hostip = NULL;
    char* active_path = NULL;
    char* passive_path = NULL;
    char* seperator = NULL;
    char* checkScriptPathFragment  = NULL;
    char* smsScriptPathFragment    = NULL;
    char* loginScriptPathFragment  = NULL;
    char* passScriptPathFragment   = NULL;
    char* offlineScriptPathFragment= NULL;
    char* portalScriptPathFragment = NULL;
    char* updatePortalPathFragment = NULL;
    char* dloadPortalPathFragment  = NULL;
    char* msgScriptPathFragment    = NULL;
    char* pingScriptPathFragment   = NULL;
    char* authScriptPathFragment   = NULL;
    char line[MAX_BUF];
    char* p1;
    char* p2;
    int tcp_port;
    int http_port;
    int ssl_port;
    int ssl_available;
    int opcode;
    t_auth_serv* new;
    t_auth_serv* tmp;

    if(!mgmt)
    {
        debug(LOG_ERR, "auth_serv_mgmt null");
        return;
    }
    /* Defaults */
    active_path = safe_strdup(DEFAULT_ACTIVE_PATH);
    passive_path = safe_strdup(DEFAULT_PASSIVE_PATH);
    seperator = safe_strdup(DEFAULT_AUTHSERVREQUESTSEPERATOR);
    checkScriptPathFragment  = safe_strdup(DEFAULT_AUTHSERVCHECKPATHFRAGMENT);
    smsScriptPathFragment    = safe_strdup(DEFAULT_AUTHSERVSMSPATHFRAGMENT);
    loginScriptPathFragment  = safe_strdup(DEFAULT_AUTHSERVLOGINPATHFRAGMENT);
    passScriptPathFragment   = safe_strdup(DEFAULT_AUTHSERVPASSPATHFRAGMENT);
    offlineScriptPathFragment= safe_strdup(DEFAULT_AUTHSERVOFFLINEPATHFRAGMENT);
    portalScriptPathFragment = safe_strdup(DEFAULT_AUTHSERVPORTALPATHFRAGMENT);
    updatePortalPathFragment = safe_strdup(DEFAULT_UPDATEPORTALPATHFRAGMENT);
    dloadPortalPathFragment  = safe_strdup(DEFAULT_DLOADPORTALPATHFRAGMENT);
    msgScriptPathFragment    = safe_strdup(DEFAULT_AUTHSERVMSGPATHFRAGMENT);
    pingScriptPathFragment   = safe_strdup(DEFAULT_AUTHSERVPINGPATHFRAGMENT);
    authScriptPathFragment   = safe_strdup(DEFAULT_AUTHSERVAUTHPATHFRAGMENT);
    tcp_port  = 0;  // DEFAULT_AUTHAGENTTCPPORT;
    http_port = 0;  //DEFAULT_AUTHAGENTHTTPPORT;
    ssl_port  = DEFAULT_AUTHSERVSSLPORT;
    ssl_available = DEFAULT_AUTHSERVSSLAVAILABLE;

    /* Parsing loop */
    while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
        (*linenum)++;           /* increment line counter. */

        /* skip leading blank spaces */
        for (p1 = line; isblank(*p1); p1++) ;

        /* End at end of line */
        if ((p2 = strchr(p1, '#')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\r')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\n')) != NULL) {
            *p2 = '\0';
        }

        /* trim all blanks at the end of the line */
        for (p2 = (p2 != NULL ? p2 - 1 : &line[MAX_BUF - 2]); isblank(*p2) && p2 > p1; p2--) {
            *p2 = '\0';
        }

        /* next, we coopt the parsing of the regular config */
        if (strlen(p1) > 0) {
            p2 = p1;
            /* keep going until word boundary is found. */
            while ((*p2 != '\0') && (!isblank(*p2)))
                p2++;

            /* Terminate first word. */
            *p2 = '\0';
            p2++;

            /* skip all further blanks. */
            while (isblank(*p2))
                p2++;

            /* Get opcode */
            opcode = config_parse_token(p1, filename, *linenum);

            switch (opcode) {
            case oAuthServHostname:
                /* Coverity rightfully pointed out we could have duplicates here. */
                if (NULL != hostname)
                    free(hostname);
                hostname = safe_strdup(p2);
                break;
            case oAuthServHostip:
                /* Coverity rightfully pointed out we could have duplicates here. */
                if (NULL != hostip)
                    free(hostip);
                hostip = safe_strdup(p2);
                break;
            case oAuthServActivePath:
                free(active_path);
                active_path = safe_strdup(p2);
                break;
            case oAuthServPassivePath:
                free(passive_path);
                passive_path = safe_strdup(p2);
                break;
            case oAuthServSeperator:
                free(seperator);
                seperator = safe_strdup(p2);
                break;
            case oAuthServCheckScriptPathFragment:
                free(checkScriptPathFragment);
                checkScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServSmsScriptPathFragment:
                free(smsScriptPathFragment);
                smsScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServLoginScriptPathFragment:
                free(loginScriptPathFragment);
                loginScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServPassScriptPathFragment:
                free(passScriptPathFragment);
                passScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServOfflineScriptPathFragment:
                free(offlineScriptPathFragment);
                offlineScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServPortalScriptPathFragment:
                free(portalScriptPathFragment);
                portalScriptPathFragment = safe_strdup(p2);
                break;
            case oUpdatePortalPathFragment:
                free(updatePortalPathFragment);
                updatePortalPathFragment = safe_strdup(p2);
                break;
            case oDLoadPortalPathFragment:
                free(dloadPortalPathFragment);
                dloadPortalPathFragment = safe_strdup(p2);
                break;
            case oAuthServMsgScriptPathFragment:
                free(msgScriptPathFragment);
                msgScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServPingScriptPathFragment:
                free(pingScriptPathFragment);
                pingScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServAuthScriptPathFragment:
                free(authScriptPathFragment);
                authScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServSSLPort:
                ssl_port = atoi(p2);
                break;
            case oAuthAgentTCPPort:
                tcp_port = atoi(p2);
                break;
            case oAuthServHTTPPort:
                http_port = atoi(p2);
                break;
            case oAuthServSSLAvailable:
                ssl_available = parse_boolean_value(p2);
                if (ssl_available < 0) {
                    debug(LOG_WARNING, "Bad syntax for Parameter: SSLAvailable on line %d " "in %s."
                        "The syntax is yes or no." , *linenum, filename);
                    rhy_exit(-1);
                }
                break;
            case oBadOption:
            default:
                debug(LOG_ERR, "Bad option on line %d " "in %s.", *linenum, filename);
                debug(LOG_ERR, "Exiting...");
                rhy_exit(-1);
                break;
            }
        }
    }

    /* only proceed if we have an host and a path */
    if (NULL == hostname && NULL == hostip) {
        free(active_path);
        free(passive_path);
        free(seperator);
        free(checkScriptPathFragment);
        free(smsScriptPathFragment);
        free(loginScriptPathFragment);
        free(passScriptPathFragment);
        free(offlineScriptPathFragment);
        free(portalScriptPathFragment);
        free(updatePortalPathFragment);
        free(dloadPortalPathFragment);
        free(msgScriptPathFragment);
        free(pingScriptPathFragment);
        free(authScriptPathFragment);
        return;
    }

    debug(LOG_INFO, "Adding %s[%s] (TCP:%d) (HTTP:%d) (SSL: %d) %s %s to the %s list", 
               hostname, hostip, tcp_port, http_port, ssl_port, active_path, passive_path, mgmt->name);

    /* Allocate memory */
    new = safe_malloc(sizeof(t_auth_serv));

    /* Fill in struct */
    new->authserv_hostname = hostname;
    new->authserv_hostip = hostip;
    new->authserv_use_ssl = ssl_available;
    new->active_path = active_path;
    new->passive_path = passive_path;
    new->authserv_seperator = seperator;
    new->authserv_check_script_path_fragment  = checkScriptPathFragment;
    new->authserv_sms_script_path_fragment    = smsScriptPathFragment;
    new->authserv_login_script_path_fragment  = loginScriptPathFragment;
    new->authserv_pass_script_path_fragment   = passScriptPathFragment;
    new->authserv_offline_script_path_fragment= offlineScriptPathFragment;
    new->authserv_portal_script_path_fragment = portalScriptPathFragment;
    new->authserv_update_portal_path_fragment = updatePortalPathFragment;
    new->authserv_dload_portal_path_fragment  = dloadPortalPathFragment;
    new->authserv_msg_script_path_fragment    = msgScriptPathFragment;
    new->authserv_ping_script_path_fragment   = pingScriptPathFragment;
    new->authserv_auth_script_path_fragment   = authScriptPathFragment;
    new->authagent_tcp_port = tcp_port;
    new->authserv_http_port = http_port;
    new->authserv_ssl_port = ssl_port;
    new->status = E_AUTH_CONN_INIT;
    new->socket_fd  = -1;
    new->auth_server_mgmt  = mgmt;
    /* If it's the first, add to config, else append to last server */
    if (mgmt->auth_server == NULL) {
        mgmt->auth_server = new;
    } else {
        for (tmp = mgmt->auth_server; tmp->next != NULL; tmp = tmp->next) ;
        tmp->next = new;
    }

    debug(LOG_DEBUG, "%s added",  mgmt->name);
}

static void parse_auth_server(FILE* file, const char* filename, int* linenum)
{
#if 0
    char* hostname = NULL;
    char* hostip = NULL;
    char* active_path = NULL;
    char* passive_path = NULL;
    char* seperator = NULL;
    char* checkScriptPathFragment  = NULL;
    char* smsScriptPathFragment    = NULL;
    char* loginScriptPathFragment  = NULL;
    char* passScriptPathFragment   = NULL;
    char* offlineScriptPathFragment= NULL;
    char* portalScriptPathFragment = NULL;
    char* updatePortalPathFragment = NULL;
    char* dloadPortalPathFragment  = NULL;
    char* msgScriptPathFragment    = NULL;
    char* pingScriptPathFragment   = NULL;
    char* authScriptPathFragment   = NULL;
    char line[MAX_BUF];
    char* p1;
    char* p2;
    int http_port;
    int ssl_port;
    int ssl_available;
    int opcode;
    t_auth_serv *new;
    t_auth_serv* tmp;
    
    /* Defaults */
    active_path = safe_strdup(DEFAULT_ACTIVE_PATH);
    passive_path = safe_strdup(DEFAULT_PASSIVE_PATH);
    seperator = safe_strdup(DEFAULT_AUTHSERVREQUESTSEPERATOR);
    checkScriptPathFragment  = safe_strdup(DEFAULT_AUTHSERVCHECKPATHFRAGMENT);
    smsScriptPathFragment    = safe_strdup(DEFAULT_AUTHSERVSMSPATHFRAGMENT);
    loginScriptPathFragment  = safe_strdup(DEFAULT_AUTHSERVLOGINPATHFRAGMENT);
    passScriptPathFragment   = safe_strdup(DEFAULT_AUTHSERVPASSPATHFRAGMENT);
    offlineScriptPathFragment= safe_strdup(DEFAULT_AUTHSERVOFFLINEPATHFRAGMENT);
    portalScriptPathFragment = safe_strdup(DEFAULT_AUTHSERVPORTALPATHFRAGMENT);
    updatePortalPathFragment = safe_strdup(DEFAULT_UPDATEPORTALPATHFRAGMENT);
    dloadPortalPathFragment  = safe_strdup(DEFAULT_DLOADPORTALPATHFRAGMENT);
    msgScriptPathFragment    = safe_strdup(DEFAULT_AUTHSERVMSGPATHFRAGMENT);
    pingScriptPathFragment   = safe_strdup(DEFAULT_AUTHSERVPINGPATHFRAGMENT);
    authScriptPathFragment   = safe_strdup(DEFAULT_AUTHSERVAUTHPATHFRAGMENT);
    http_port = DEFAULT_AUTHSERVPORT;
    ssl_port = DEFAULT_AUTHSERVSSLPORT;
    ssl_available = DEFAULT_AUTHSERVSSLAVAILABLE;

    /* Parsing loop */
    while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
        (*linenum)++;           /* increment line counter. */

        /* skip leading blank spaces */
        for (p1 = line; isblank(*p1); p1++) ;

        /* End at end of line */
        if ((p2 = strchr(p1, '#')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\r')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\n')) != NULL) {
            *p2 = '\0';
        }

        /* trim all blanks at the end of the line */
        for (p2 = (p2 != NULL ? p2 - 1 : &line[MAX_BUF - 2]); isblank(*p2) && p2 > p1; p2--) {
            *p2 = '\0';
        }

        /* next, we coopt the parsing of the regular config */
        if (strlen(p1) > 0) {
            p2 = p1;
            /* keep going until word boundary is found. */
            while ((*p2 != '\0') && (!isblank(*p2)))
                p2++;

            /* Terminate first word. */
            *p2 = '\0';
            p2++;

            /* skip all further blanks. */
            while (isblank(*p2))
                p2++;

            /* Get opcode */
            opcode = config_parse_token(p1, filename, *linenum);

            switch (opcode) {
            case oAuthServHostname:
                /* Coverity rightfully pointed out we could have duplicates here. */
                if (NULL != hostname)
                    free(hostname);
                hostname = safe_strdup(p2);
                break;
            case oAuthServHostip:
                /* Coverity rightfully pointed out we could have duplicates here. */
                if (NULL != hostip)
                    free(hostip);
                hostip = safe_strdup(p2);
                break;
            case oAuthServActivePath:
                free(active_path);
                active_path = safe_strdup(p2);
                break;
            case oAuthServPassivePath:
                free(passive_path);
                passive_path = safe_strdup(p2);
                break;
            case oAuthServSeperator:
                free(seperator);
                seperator = safe_strdup(p2);
                break;
            case oAuthServCheckScriptPathFragment:
                free(checkScriptPathFragment);
                checkScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServSmsScriptPathFragment:
                free(smsScriptPathFragment);
                smsScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServLoginScriptPathFragment:
                free(loginScriptPathFragment);
                loginScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServPassScriptPathFragment:
                free(passScriptPathFragment);
                passScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServOfflineScriptPathFragment:
                free(offlineScriptPathFragment);
                offlineScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServPortalScriptPathFragment:
                free(portalScriptPathFragment);
                portalScriptPathFragment = safe_strdup(p2);
                break;
            case oUpdatePortalPathFragment:
                free(updatePortalPathFragment);
                updatePortalPathFragment = safe_strdup(p2);
                break;
            case oDLoadPortalPathFragment:
                free(dloadPortalPathFragment);
                dloadPortalPathFragment = safe_strdup(p2);
                break;
            case oAuthServMsgScriptPathFragment:
                free(msgScriptPathFragment);
                msgScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServPingScriptPathFragment:
                free(pingScriptPathFragment);
                pingScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServAuthScriptPathFragment:
                free(authScriptPathFragment);
                authScriptPathFragment = safe_strdup(p2);
                break;
            case oAuthServSSLPort:
                ssl_port = atoi(p2);
                break;
            case oAuthServHTTPPort:
                http_port = atoi(p2);
                break;
            case oAuthServSSLAvailable:
                ssl_available = parse_boolean_value(p2);
                if (ssl_available < 0) {
                    debug(LOG_WARNING, "Bad syntax for Parameter: SSLAvailable on line %d " "in %s."
                        "The syntax is yes or no." , *linenum, filename);
                    rhy_exit(-1);
                }
                break;
            case oBadOption:
            default:
                debug(LOG_ERR, "Bad option on line %d " "in %s.", *linenum, filename);
                debug(LOG_ERR, "Exiting...");
                rhy_exit(-1);
                break;
            }
        }
    }

    /* only proceed if we have an host and a path */
    if (NULL == hostname && NULL == hostip) {
        free(active_path);
        free(passive_path);
        free(seperator);
        free(checkScriptPathFragment);
        free(smsScriptPathFragment);
        free(loginScriptPathFragment);
        free(passScriptPathFragment);
        free(offlineScriptPathFragment);
        free(portalScriptPathFragment);
        free(updatePortalPathFragment);
        free(dloadPortalPathFragment);
        free(msgScriptPathFragment);
        free(pingScriptPathFragment);
        free(authScriptPathFragment);
        return;
    }

    debug(LOG_INFO, "Adding %s[%s]:%d (SSL: %d) %s %s to the auth server list", 
               hostname, hostip, http_port, ssl_port, active_path, passive_path);

    /* Allocate memory */
    new = safe_malloc(sizeof(t_auth_serv));

    /* Fill in struct */
    new->authserv_hostname = hostname;
    new->authserv_hostip = hostip;
    new->authserv_use_ssl = ssl_available;
    new->active_path = active_path;
    new->passive_path = passive_path;
    new->authserv_seperator = seperator;
    new->authserv_check_script_path_fragment  = checkScriptPathFragment;
    new->authserv_sms_script_path_fragment    = smsScriptPathFragment;
    new->authserv_login_script_path_fragment  = loginScriptPathFragment;
    new->authserv_pass_script_path_fragment   = passScriptPathFragment;
    new->authserv_offline_script_path_fragment= offlineScriptPathFragment;
    new->authserv_portal_script_path_fragment = portalScriptPathFragment;
    new->authserv_update_portal_path_fragment = updatePortalPathFragment;
    new->authserv_dload_portal_path_fragment  = dloadPortalPathFragment;
    new->authserv_msg_script_path_fragment    = msgScriptPathFragment;
    new->authserv_ping_script_path_fragment   = pingScriptPathFragment;
    new->authserv_auth_script_path_fragment   = authScriptPathFragment;
    new->authserv_http_port = http_port;
    new->authserv_ssl_port = ssl_port;
    /* If it's the first, add to config, else append to last server */
    tmp = get_auth_server();
    if (tmp == NULL) {
        tmp = new;
    } else {
        for (; tmp->next != NULL; tmp = tmp->next) ;
        tmp->next = new;
    }

    debug(LOG_DEBUG, "Auth server added");
#else
    parse_auth_server2(file, filename, linenum, &config.auth_servers);
#endif
}

/**
Advance to the next word
@param s string to parse, this is the next_word pointer, the value of s
    when the macro is called is the current word, after the macro
    completes, s contains the beginning of the NEXT word, so you
    need to save s to something else before doing TO_NEXT_WORD
@param e should be 0 when calling TO_NEXT_WORD(), it'll be changed to 1
    if the end of the string is reached.
*/
#define TO_NEXT_WORD(s, e) do { \
    while (*s != '\0' && !isblank(*s)) { \
        s++; \
    } \
    if (*s != '\0') { \
        *s = '\0'; \
        s++; \
        while (isblank(*s)) \
            s++; \
    } else { \
        e = 1; \
    } \
} while (0)

/** @internal
Parses firewall rule set information
*/
static void parse_firewall_ruleset(const char* ruleset, FILE* file, const char* filename, int* linenum)
{
    char line[MAX_BUF], *p1, *p2;
    int opcode;

    debug(LOG_DEBUG, "Adding Firewall Rule Set %s", ruleset);

    /* Parsing loop */
    while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
        (*linenum)++;           /* increment line counter. */

        /* skip leading blank spaces */
        for (p1 = line; isblank(*p1); p1++) ;

        /* End at end of line */
        if ((p2 = strchr(p1, '#')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\r')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\n')) != NULL) {
            *p2 = '\0';
        }

        /* next, we coopt the parsing of the regular config */
        if (strlen(p1) > 0) {
            p2 = p1;
            /* keep going until word boundary is found. */
            while ((*p2 != '\0') && (!isblank(*p2)))
                p2++;

            /* Terminate first word. */
            *p2 = '\0';
            p2++;

            /* skip all further blanks. */
            while (isblank(*p2))
                p2++;

            /* Get opcode */
            opcode = config_parse_token(p1, filename, *linenum);

            debug(LOG_DEBUG, "p1 = [%s]; p2 = [%s]", p1, p2);

            switch (opcode) {
            case oFirewallRule:
                _parse_firewall_rule(ruleset, p2);
                break;

            case oBadOption:
            default:
                debug(LOG_ERR, "Bad option on line %d " "in %s.", *linenum, filename);
                debug(LOG_ERR, "Exiting...");
                rhy_exit(-1);
                break;
            }
        }
    }

    debug(LOG_DEBUG, "Firewall Rule Set %s added.", ruleset);
}

/** @internal
Helper for parse_firewall_ruleset.  Parses a single rule in a ruleset
*/
static int _parse_firewall_rule(const char* ruleset, char* leftover)
{
    int i;
    t_firewall_target target = TARGET_REJECT;     /**< firewall target */
    int all_nums = 1;     /**< If 0, port contained non-numerics */
    int finished = 0;     /**< reached end of line */
    char *token = NULL;     /**< First word */
    char *port = NULL;     /**< port to open/block */
    char *protocol = NULL;     /**< protocol to block, tcp/udp/icmp */
    char *mask = NULL;     /**< Netmask */
    char *other_kw = NULL;     /**< other key word */
    int mask_is_ipset = 0;
    t_firewall_ruleset *tmpr;
    t_firewall_ruleset *tmpr2;
    t_firewall_rule *tmp;
    t_firewall_rule *tmp2;

    debug(LOG_DEBUG, "leftover: %s", leftover);

    /* lower case */
    for (i = 0; *(leftover + i) != '\0' && (*(leftover + i) = tolower((unsigned char)*(leftover + i))); i++) ;

    token = leftover;
    TO_NEXT_WORD(leftover, finished);

    /* Parse token */
    if (!strcasecmp(token, "block") || finished) {
        target = TARGET_REJECT;
    } else if (!strcasecmp(token, "drop")) {
        target = TARGET_DROP;
    } else if (!strcasecmp(token, "allow")) {
        target = TARGET_ACCEPT;
    } else if (!strcasecmp(token, "log")) {
        target = TARGET_LOG;
    } else if (!strcasecmp(token, "ulog")) {
        target = TARGET_ULOG;
    } else {
        debug(LOG_ERR, "Invalid rule type %s, expecting " "\"block\",\"drop\",\"allow\",\"log\" or \"ulog\"", token);
        return -1;
    }

    /* Parse the remainder */
    /* Get the protocol */
    if (strncmp(leftover, "tcp", 3) == 0 || strncmp(leftover, "udp", 3) == 0 || strncmp(leftover, "icmp", 4) == 0) {
        protocol = leftover;
        TO_NEXT_WORD(leftover, finished);
    }

    /* Get the optional port or port range */
    if (strncmp(leftover, "port", 4) == 0) {
        TO_NEXT_WORD(leftover, finished);
        /* Get port now */
        port = leftover;
        TO_NEXT_WORD(leftover, finished);
        for (i = 0; *(port + i) != '\0'; i++)
            if (!isdigit((unsigned char)*(port + i)) && ((unsigned char)*(port + i) != ':'))
                all_nums = 0;   /*< No longer only digits */
        if (!all_nums) {
            debug(LOG_ERR, "ERROR: config file, section FirewallRuleset %s. " "Invalid port %s", ruleset, port);
            return -3;          /*< Fail */
        }
    }

    /* Now, further stuff is optional */
    if (!finished) {
        /* should be exactly "to" or "to-ipset" */
        other_kw = leftover;
        TO_NEXT_WORD(leftover, finished);
        if (!finished) {
            /* Get arg now and check validity in next section */
            mask = leftover;
        }
        if (strncmp(other_kw, "to-ipset", 8) == 0 && !finished) {
            mask_is_ipset = 1;
        }
        TO_NEXT_WORD(leftover, finished);
        if (!finished) {
            debug(LOG_WARNING, "Ignoring trailining string after successfully parsing rule: %s", leftover);
        }
    }
    /* Generate rule record */
    tmp = safe_malloc(sizeof(t_firewall_rule));
    tmp->target = target;
    tmp->mask_is_ipset = mask_is_ipset;
    if (protocol != NULL)
        tmp->protocol = safe_strdup(protocol);
    if (port != NULL)
        tmp->port = safe_strdup(port);
    if (mask == NULL)
        tmp->mask = safe_strdup("0.0.0.0/0");
    else
        tmp->mask = safe_strdup(mask);

    debug(LOG_INFO, "Adding Firewall Rule %s %s port %s to %s", token, tmp->protocol, tmp->port, tmp->mask);

    /* Append the rule record */
    if (config.rulesets == NULL) {
         config.rulesets = safe_malloc(sizeof(t_firewall_ruleset));
        config.rulesets->name = safe_strdup(ruleset);
        tmpr = config.rulesets;
    } else {
        tmpr2 = tmpr = config.rulesets;
        while (tmpr != NULL && (strcmp(tmpr->name, ruleset) != 0)) {
            tmpr2 = tmpr;
            tmpr = tmpr->next;
        }
        if (tmpr == NULL) {
            /* Rule did not exist */
            tmpr = safe_malloc(sizeof(t_firewall_ruleset));
            tmpr->name = safe_strdup(ruleset);
            tmpr2->next = tmpr;
        }
    }

    /* At this point, tmpr == current ruleset */
    if (tmpr->rules == NULL) {
        /* No rules... */
        tmpr->rules = tmp;
    } else {
        tmp2 = tmpr->rules;
        while (tmp2->next != NULL)
            tmp2 = tmp2->next;
        tmp2->next = tmp;
    }

    return 1;
}

t_firewall_rule* get_ruleset(const char* ruleset)
{
    t_firewall_ruleset *tmp;

    for (tmp = config.rulesets; tmp != NULL && strcmp(tmp->name, ruleset) != 0; tmp = tmp->next) ;

    if (tmp == NULL)
        return NULL;

    return (tmp->rules);
}

/**
@param filename Full path of the configuration file to be read 
*/
void config_read(const char* filename)
{
    FILE *fd;
    char line[MAX_BUF], *s, *p1, *p2, *rawarg = NULL;
    int linenum = 0, opcode, value;
    size_t len;

    debug(LOG_INFO, "Reading configuration file '%s'", filename);

    if (!(fd = fopen(filename, "r"))) {
        debug(LOG_ERR, "Could not open configuration file '%s', " "exiting...", filename);
        rhy_exit(-1);
    }

    while (!feof(fd) && fgets(line, MAX_BUF, fd)) {
        linenum++;
        s = line;

        if (s[strlen(s) - 1] == '\n')
            s[strlen(s) - 1] = '\0';

        if ((p1 = strchr(s, ' '))) {
            p1[0] = '\0';
        } else if ((p1 = strchr(s, '\t'))) {
            p1[0] = '\0';
        }

        if (p1) {
            p1++;

            // Trim leading spaces
            len = strlen(p1);
            while (*p1 && len) {
                if (*p1 == ' ')
                    p1++;
                else
                    break;
                len = strlen(p1);
            }
            rawarg = safe_strdup(p1);
            if ((p2 = strchr(p1, ' '))) {
                p2[0] = '\0';
            } else if ((p2 = strstr(p1, "\r\n"))) {
                p2[0] = '\0';
            } else if ((p2 = strchr(p1, '\n'))) {
                p2[0] = '\0';
            }
        }

        if (p1 && p1[0] != '\0') {
            /* Strip trailing spaces */

            if ((strncmp(s, "#", 1)) != 0) {
                debug(LOG_DEBUG, "Parsing token: %s, " "value: %s", s, p1);
                opcode = config_parse_token(s, filename, linenum);

                switch (opcode) {
                case oDeltaTraffic:
                    config.deltatraffic = parse_boolean_value(p1);
                    break;
                case oDaemon:
                    if (config.daemon == -1 && ((value = parse_boolean_value(p1)) != -1)) {
                        config.daemon = value;
                        if (config.daemon > 0) {
                            debugconf.log_stderr = 0;
                        } else {
                            debugconf.log_stderr = 1;
                        }
                    }
                    break;
                case oExternalInterface:
                    CONFIG_SET(external_interface, p1);
                    break;
                case oExternalAddress:
                    CONFIG_SET(external_address, p1);
                    break;
                case oExternalPort:
                    sscanf(p1, "%d", &config.external_web_port);
                    break;
                case oGatewayID:
                    CONFIG_SET(gw_id, p1);
                    break;
                case oGatewayInterface:
                    CONFIG_SET(gw_interface, p1);
                    break;
                case oGatewayAddress:
                    CONFIG_SET(gw_address, p1);
                    break;
                case oGatewayPort:
                    sscanf(p1, "%d", &config.gw_port);
                    break;
                case oAuthServer:
                    parse_auth_server(fd, filename, &linenum);
                    break;
                case oAuthAgent:
                    parse_auth_server2(fd, filename, &linenum, &config.auth_agents);
                    break;
                case oFirewallRuleSet:
                    parse_firewall_ruleset(p1, fd, filename, &linenum);
                    break;
                case oTrustedMACList:
                    parse_trusted_mac_list(p1);
                    break;
                case oPopularServers:
                    parse_popular_servers(rawarg);
                    break;
                case oHTTPDName:
                    CONFIG_SET(httpdname, p1);
                    break;
                case oHTTPDMaxConn:
                    sscanf(p1, "%d", &config.httpdmaxconn);
                    break;
                case oHTTPDRealm:
                    CONFIG_SET(httpdrealm, p1);
                    break;
                case oHTTPDUsername:
                    CONFIG_SET(httpdusername, p1);
                    break;
                case oHTTPDPassword:
                    CONFIG_SET(httpdpassword, p1);
                    break;
                case oMaxClientNum:
                    sscanf(p1, "%d", &config.max_client_num);
                    if(config.max_client_num < MIN_CLIENTMAXNUM || config.max_client_num > MAX_CLIENTMAXNUM)
                    {
                        config.max_client_num = DEFAULT_CLIENTMAXNUM;
                    }
                    break;
                case oCheckInterval:
                    sscanf(p1, "%d", &config.checkinterval);
                    if(config.checkinterval < MIN_CHECKINTERVAL || config.checkinterval > MAX_CHECKINTERVAL)
                    {
                        debug(LOG_WARNING, "checkinterval [%d] is out of scope [%d, %d]", 
                                                         config.checkinterval, MIN_CHECKINTERVAL, MAX_CHECKINTERVAL);
                        config.checkinterval = DEFAULT_CHECKINTERVAL;
                    }
                    break;
                case oWdctlSocket:
                    CONFIG_SET(wdctl_sock, p1);
                    break;
                case oClientTimeout:
                    sscanf(p1, "%d", &config.clienttimeout);
                    break;
                case oSyslogFacility:
                    sscanf(p1, "%d", &debugconf.syslog_facility);
                    break;
                case oHtmlMessageFile:
                    CONFIG_SET(htmlmsgfile, p1);
                    break;
                case oProxyPort:
                    sscanf(p1, "%d", &config.proxy_port);
                    break;
                case oSSLCertPath:
                    CONFIG_SET(ssl_certs, p1);
#ifndef USE_CYASSL
                    debug(LOG_WARNING, "SSLCertPath is set but not SSL compiled in. Ignoring!");
#endif
                    break;
                case oSSLPeerVerification:
                    config.ssl_verify = parse_boolean_value(p1);
                    if (config.ssl_verify < 0) {
                        debug(LOG_WARNING, "Bad syntax for Parameter: SSLPeerVerification on line %d " "in %s."
                            "The syntax is yes or no." , linenum, filename);
                        rhy_exit(-1);
                    }
#ifndef USE_CYASSL
                    debug(LOG_WARNING, "SSLPeerVerification is set but no SSL compiled in. Ignoring!");
#endif
                    break;
                case oSSLAllowedCipherList:
                    CONFIG_SET(ssl_cipher_list, p1);
#ifndef USE_CYASSL
                    debug(LOG_WARNING, "SSLAllowedCipherList is set but no SSL compiled in. Ignoring!");
#endif
                    break;
                case oSSLUseSNI:
                    config.ssl_use_sni = parse_boolean_value(p1);
                    if (config.ssl_use_sni < 0) {
                        debug(LOG_WARNING, "Bad syntax for Parameter: SSLUseSNI on line %d " "in %s."
                            "The syntax is yes or no." , linenum, filename);
                        rhy_exit(-1);
                    }
#ifndef USE_CYASSL
                    debug(LOG_WARNING, "SSLUseSNI is set but no SSL compiled in. Ignoring!");
#else
#ifndef HAVE_SNI
                    debug(LOG_WARNING, "SSLUseSNI is set but no CyaSSL SNI enabled. Ignoring!");
#endif
#endif
                    break;
                    case oHttpAccessLogFile:
                        CONFIG_SET(http_accesslog_file, p1);
                    break;
                    case oHttpErrorLogFile:
                        CONFIG_SET(http_errorlog_file, p1);
                    break;
                    case oHttpVersion:
                        if(0==strcmp(CONF_HTTP_VERSION_10, p1) || 0==strcmp(CONF_HTTP_VERSION_11, p1))
                          CONFIG_SET(http_version, p1);
                    break;
                    case oPlaceCode:
                        CONFIG_SET(place_code, p1);
                    break;
                    case oPortalCode:
                        CONFIG_SET(portal_code, p1);
                    break;
                    case oCompany:
                        CONFIG_SET(company, p1);
                    break;
                    case oCompanyId:
                        sscanf(p1, "%d", &config.company_id);
                    break;
                    case oSsid:
                        CONFIG_SET(ssid, p1);
                    break;
                    case oLessee_id:
                        CONFIG_SET(lessee_id, p1);
                    break;
                    case oPortalSavePath:
                        CONFIG_SET(portal_save_path, p1);
                    break;
                    case oFaviconIcoPath:
                        CONFIG_SET(favacon_ico_path, p1);
                    break;
                    case oSmsFlag:
                        if(0==strcmp("true", p1))
                          config.sms_flag = 1;
                        else
                          config.sms_flag = 0;
                    break;
                    case oLocalAuthFlag:
                        if(0==strcmp("true", p1))
                          config.local_auth_flag = 1;
                        else
                          config.local_auth_flag = 0;
                    break;
                    case oSemuFlag:
                        if(0==strcmp("true", p1))
                          config.semu_flag = 1;
                        else
                          config.semu_flag = 0;
                    break;
                    case oSemuPortalIp:
                        CONFIG_SET(semu_portal_ip, p1);
                    break;
                    case oDpiFlag:
                        if(0==strcmp("true", p1))
                          config.dpi_flag = 1;
                        else
                          config.dpi_flag = 0;
                    break;
                    case oDpiBPF:
                        p2=p1;
                        while(*p2!='\0')
                        {
                          if(*p2=='*') *p2=' ';     /* Take '*' as BPF original seperator and replace to space */
                          p2++;
                        }
                        CONFIG_SET(dpi_bpf, p1);
                    break;
                    case oDpiLogFile:
                        CONFIG_SET(dpi_log_file, p1);
                    break;

                case oBadOption:
                    /* FALL THROUGH */
                default:
                    debug(LOG_ERR, "Bad option on line %d " "in %s.", linenum, filename);
                    debug(LOG_ERR, "Exiting...");
                    rhy_exit(-1);
                    break;
                }
            }
        }
        if (rawarg) {
            free(rawarg);
            rawarg = NULL;
        }
    }

    if (!IS_NULL_CONFIG(httpdusername) && IS_NULL_CONFIG(httpdpassword)) {
        debug(LOG_ERR, "HTTPDUserName requires a HTTPDPassword to be set.");
        rhy_exit(-1);
    }

    fclose(fd);
}

/** @internal
Parses a boolean value from the config file
*/
static int parse_boolean_value(char* line)
{
    if (strcasecmp(line, "yes") == 0) {
        return 1;
    }
    if (strcasecmp(line, "no") == 0) {
        return 0;
    }
    if (strcmp(line, "1") == 0) {
        return 1;
    }
    if (strcmp(line, "0") == 0) {
        return 0;
    }

    return -1;
}

/**
 * Parse possiblemac to see if it is valid MAC address format */
int check_mac_format(char* possiblemac)
{
    char hex2[3];
    return
        sscanf(possiblemac,
               "%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]",
               hex2, hex2, hex2, hex2, hex2, hex2) == 6;
}

/** @internal
 * Parse the trusted mac list.
 */
static void parse_trusted_mac_list(const char* ptr)
{
    char *ptrcopy = NULL;
    char *possiblemac = NULL;
    char *mac = NULL;
    t_trusted_mac *p = NULL;

    debug(LOG_DEBUG, "Parsing string [%s] for trusted MAC addresses", ptr);

    mac = safe_malloc(MAX_MAC_ADDR_LEN);

    /* strsep modifies original, so let's make a copy */
    ptrcopy = safe_strdup(ptr);

    while ((possiblemac = strsep(&ptrcopy, ","))) {
        /* check for valid format */
        if (!check_mac_format(possiblemac)) 
		{
            debug(LOG_ERR, "[%s] not a valid MAC to trust. See option TrustedMACList in *.conf for correct this mistake.", possiblemac);
            free(ptrcopy);
            free(mac);
            return;
        } 
		else
		{
            if (sscanf(possiblemac, " %17[A-Fa-f0-9:]", mac) == 1) 
			{
                /* Copy mac to the list */

                debug(LOG_INFO, "Adding MAC address [%s] to trusted list", mac);

                if (config.trustedmaclist == NULL)
				{
                    config.trustedmaclist = safe_malloc(sizeof(t_trusted_mac));
                    config.trustedmaclist->mac = safe_strdup(mac);
                    config.trustedmaclist->next = NULL;
                } 
				else
				{
                    int skipmac;
                    /* Advance to the last entry */
                    p = config.trustedmaclist;
                    skipmac = 0;
                    /* Check before loop to handle case were mac is a duplicate
                     * of the first and only item in the list so far.
                     */
                    if (0 == strcmp(p->mac, mac))
					{
                        skipmac = 1;
                    }
                    while (p->next != NULL) {
                        if (0 == strcmp(p->mac, mac)) 
						{
                            skipmac = 1;
                        }
                        p = p->next;
                    }
                    if (!skipmac) 
					{
                        p->next = safe_malloc(sizeof(t_trusted_mac));
                        p = p->next;
                        p->mac = safe_strdup(mac);
                        p->next = NULL;
                    } 
					else
					{
                        debug(LOG_ERR, "MAC[%s] already on trusted list. See option TrustedMACList in *.conf file ", mac);
                    }
                }
            }
        }
    }

    free(ptrcopy);

    free(mac);

}

/** @internal
 * Add a popular server to the list. It prepends for simplicity.
 * @param server The hostname to add.
 */
static void add_popular_server(const char* server)
{
    t_popular_server *p = NULL;

    p = (t_popular_server *)safe_malloc(sizeof(t_popular_server));
    p->hostname = safe_strdup(server);

    if (config.popular_servers == NULL) {
        p->next = NULL;
        config.popular_servers = p;
    } else {
        p->next = config.popular_servers;
        config.popular_servers = p;
    }
}

static void parse_popular_servers(const char* ptr)
{
    char *ptrcopy = NULL;
    char *hostname = NULL;
    char *tmp = NULL;

    debug(LOG_DEBUG, "Parsing string [%s] for popular servers", ptr);

    /* strsep modifies original, so let's make a copy */
    ptrcopy = safe_strdup(ptr);

    while ((hostname = strsep(&ptrcopy, ","))) {  /* hostname does *not* need allocation. strsep
                                                     provides a pointer in ptrcopy. */
        /* Skip leading spaces. */
        while (*hostname != '\0' && isblank(*hostname)) { 
            hostname++;
        }
        if (*hostname == '\0') {  /* Equivalent to strcmp(hostname, "") == 0 */
            continue;
        }
        /* Remove any trailing blanks. */
        tmp = hostname;
        while (*tmp != '\0' && !isblank(*tmp)) {
            tmp++;
        }
        if (*tmp != '\0' && isblank(*tmp)) {
            *tmp = '\0';
        }
        debug(LOG_INFO, "Adding Popular Server [%s] to list", hostname);
        add_popular_server(hostname);
    }

    free(ptrcopy);
}

/** Verifies if the configuration is complete and valid.  Terminates the program if it isn't */
void config_validate(void)
{
    config_notnull(config.gw_interface, "GatewayInterface");
    config_notnull(config.auth_servers.auth_server, "AuthServer");
    config_notnull(config.auth_agents.auth_server, "AuthAgent");
    config_notnull(config.httpdusername, "HTTPDUserName");
    config_notnull(config.httpdpassword, "HTTPDPassword");
    validate_popular_servers();
    validate_portal_version();

    if (missing_parms) {
        debug(LOG_ERR, "Configuration is not complete, exiting...");
        rhy_exit(-1);
    }
}

/** @internal
 * Validate portal version.
 */
static void validate_portal_version(void)
{
    char version_file_path[PORTAL_VERSTRING_LEN*2]={0};
    char version_temp[PORTAL_VERSTRING_LEN]={0};
    FILE *fh = NULL;
    
    if(config.portal_save_path == NULL) {
        missing_parms++;
        debug(LOG_WARNING, "validate portal_save_path not set in config file and will cause updating portal version fail.");
        return;
    }
    
    snprintf(version_file_path, sizeof(version_file_path) - 1, "%s/%s", config.portal_save_path, "portal_version");
    debug(LOG_DEBUG, "Read portal_version from file:%s", version_file_path);
    
    if((fh = fopen(version_file_path, "r"))) 
    {
        if (fscanf(fh, "portal_version:%s", version_temp) != 1)
        {
            debug(LOG_ERR, "Read portal_version, failed to read portal_version");
        }
        else
        {
            strncpy(portal_version, version_temp, PORTAL_VERSTRING_LEN-1);
            portal_version[PORTAL_VERSTRING_LEN-1] = 0;
            debug(LOG_INFO, "Read portal_version from file:%s, portal_version:%s", version_file_path, portal_version);
        }
    }
    else
    {
        debug(LOG_DEBUG, "File:%s does NOT exist, create and write new file.", version_file_path);
        if((fh = fopen(version_file_path, "w")))
        {
            snprintf(version_temp, sizeof(version_temp) - 1, "portal_version:%s", portal_version);
            fwrite(version_temp, sizeof(version_temp), 1, fh);
        }
    }
    
    fclose(fh);
    fh = NULL;
    return;
}

/** @internal
 * Validate that popular servers are populated or log a warning and set a default.
 */
static void validate_popular_servers(void)
{
    if (config.popular_servers == NULL) {
        debug(LOG_WARNING, "PopularServers not set in config file, this will become fatal in a future version.");
        add_popular_server("www.baidu.com");
        add_popular_server("www.qq.com");
        add_popular_server("www.ruhaoyi.com");
        //add_popular_server("www.google.com");
        //add_popular_server("www.yahoo.com");
    }
}

/** @internal
    Verifies that a required parameter is not a null pointer
*/
static void config_notnull(const void* parm, const char* parmname)
{
    if (parm == NULL) {
        debug(LOG_ERR, "%s is not set", parmname);
        missing_parms++;
    }
}

/**
 * This function returns the current (first auth_server)
 */
t_auth_serv* get_auth_server(void)
{
    return config.auth_servers.auth_server;
}

t_auth_serv* get_auth_agent(void)
{
    return config.auth_agents.auth_server;
}

t_net_conn_mgmt_t* get_net_conn_mgmt(void)
{
    return &config.net_conn;
}

t_auth_serv_mgmt_t* get_authsvr_mgmt(void)
{
    return &config.auth_servers;
}

t_auth_serv_mgmt_t* get_authagt_mgmt(void)
{
    return &config.auth_agents;
}

char* auth_conn_state2str(t_auth_conn_state state)
{
    if(state == E_AUTH_CONN_INIT)     return "INIT";
    if(state == E_AUTH_CONN_INACTIVE) return "OFFLINE";
    if(state == E_AUTH_CONN_ACTIVE)   return "ONLINE";
    
    return "UNKOWN";
}

char* net_conn_state2str(t_internet_conn_state state)
{
    if(state == E_NET_CONN_INIT)     return "INIT";
    if(state == E_NET_CONN_INACTIVE) return "OFFLINE";
    if(state == E_NET_CONN_ACTIVE)   return "ONLINE";
    
    return "UNKOWN";
}

/**
 * This function marks the current auth_server, if it matches the argument,
 * as bad. Basically, the "bad" server becomes the last one on the list.
 */
void mark_auth_server_bad(t_auth_serv* bad_server)
{
    t_auth_serv *tmp;

    if (get_auth_server() == bad_server && bad_server->next != NULL) {
        /* Go to the last */
        for (tmp = get_auth_server(); tmp->next != NULL; tmp = tmp->next) ;
        /* Set bad server as last */
        tmp->next = bad_server;
        /* Remove bad server from start of list */
        config.auth_servers.auth_server = bad_server->next;
        /* Set the next pointe to NULL in the last element */
        bad_server->next = NULL;
    }
}

void mark_auth_server_bad2(t_auth_serv* bad_server)
{
    t_auth_serv *tmp;
    t_auth_serv_mgmt_t* serverMgmt;
    if(!bad_server || NULL == (serverMgmt=bad_server->auth_server_mgmt)) return;

    if (serverMgmt->auth_server == bad_server && bad_server->next != NULL) {
        /* Go to the last */
        for (tmp = serverMgmt->auth_server; tmp->next != NULL; tmp = tmp->next) ;
        /* Set bad server as last */
        tmp->next = bad_server;
        /* Remove bad server from start of list */
        serverMgmt->auth_server = bad_server->next;
        /* Set the next pointe to NULL in the last element */
        bad_server->next = NULL;
    }
}


