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
/** @file conf.h
    @brief Config file parsing
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _CONFIG_H_
#define _CONFIG_H_
#include "common.h"

#define USE_TCP_SOCK 1

/*@{*/
/** Defines */

/** Defaults configuration values */
#ifndef SYSCONFDIR
#define DEFAULT_CONFIGFILE "/etc/wifidog.conf"
#define DEFAULT_HTMLMSGFILE "/etc/wifidog-msg.html"
#define DEFAULT_FAVICONICO_PATH "/etc"
#else
#define DEFAULT_CONFIGFILE SYSCONFDIR"/wifidog.conf"
#define DEFAULT_HTMLMSGFILE SYSCONFDIR"/wifidog-msg.html"
#define DEFAULT_FAVICONICO_PATH SYSCONFDIR"/etc"

#endif
#define DEFAULT_DAEMON 1
#define DEFAULT_DEBUGLEVEL LOG_INFO
#define DEFAULT_HTTPDMAXCONN 10
#define DEFAULT_GATEWAYID NULL
#define DEFAULT_EXTERNALWEBPORT 55555
#define DEFAULT_GATEWAYPORT 8181
#define DEFAULT_HTTPDNAME     "RHY"
#define DEFAULT_HTTPDUSRNAME  "admin"
#define DEFAULT_HTTPDPASSWORD "rhy"
#define MIN_CLIENTMAXNUM      1
#define DEFAULT_CLIENTMAXNUM  128
#define MAX_CLIENTMAXNUM      256
#define DEFAULT_CLIENTTIMEOUT 15        /* minutes */
#define MIN_CHECKINTERVAL     30        /* seconds */
#define DEFAULT_CHECKINTERVAL 60
#define MAX_CHECKINTERVAL     120
#define DEFAULT_LOG_SYSLOG 0
#define DEFAULT_SYSLOG_FACILITY LOG_DAEMON
#define DEFAULT_WDCTL_SOCK "/tmp/wdctl.sock"
#define DEFAULT_INTERNAL_SOCK "/tmp/wifidog.sock"
#define DEFAULT_AUTHAGENTTCPPORT 9999
#define DEFAULT_AUTHAGENTHTTPPORT 9977
#define DEFAULT_AUTHSERVPORT 8080
#define DEFAULT_AUTHSERVSSLPORT 443

#define DEFAULT_DPI_BPFFILTER "udp port 53"

/** Note that DEFAULT_AUTHSERVSSLAVAILABLE must be 0 or 1, even if the config file syntax is yes or no */
#define DEFAULT_AUTHSERVSSLAVAILABLE 0
/** Note:  The path must be prefixed by /, and must be suffixed /.  Put / for the server root.*/

#define DEFAULT_ACTIVE_PATH "/WIFI_YUN/wifi/"
#define DEFAULT_PASSIVE_PATH "/WIFI_YUN/system/sms/"
#define DEFAULT_AUTHSERVREQUESTSEPERATOR "?"
#define DEFAULT_AUTHSERVCHECKPATHFRAGMENT "checkuser"
#define DEFAULT_AUTHSERVSMSPATHFRAGMENT "smsQuest"
#define DEFAULT_AUTHSERVLOGINPATHFRAGMENT "checkLogin"
#define DEFAULT_AUTHSERVPASSPATHFRAGMENT "smsPass"
#define DEFAULT_AUTHSERVOFFLINEPATHFRAGMENT "smsOffline"
#define DEFAULT_AUTHSERVPORTALPATHFRAGMENT "portal/"
#define DEFAULT_UPDATEPORTALPATHFRAGMENT "wifi/UpdatePortal"
#define DEFAULT_DLOADPORTALPATHFRAGMENT "wifi/download/"
#define DEFAULT_AUTHSERVMSGPATHFRAGMENT "gw_message.php"
#define DEFAULT_AUTHSERVPINGPATHFRAGMENT "ping/"
#define DEFAULT_AUTHSERVAUTHPATHFRAGMENT "auth/"
#define DEFAULT_AUTHSERVSSLCERTPATH "/etc/ssl/certs/"
/** Note that DEFAULT_AUTHSERVSSLNOPEERVER must be 0 or 1, even if the config file syntax is yes or no */
#define DEFAULT_AUTHSERVSSLPEERVER 1    /* 0 means: Enable peer verification */
#define DEFAULT_DELTATRAFFIC 0    /* 0 means: Enable peer verification */
#define DEFAULT_ARPTABLE "/proc/net/arp"
#define DEFAULT_AUTHSERVSSLSNI 0  /* 0 means: Disable SNI */

#define DEFAULT_PLACECODE  "1001"
#define DEFAULT_PORTALCODE "01"
#define DEFAULT_COMPANY    "RHY"
#define DEFAULT_COMPANYID  6
#define DEFAULT_SSID       "rhy"
#define DEFAULT_LESSEE_ID  "KFC"
/* flash mount on mnt directory */
#define DEFAULT_PORTAL_SAVE_PATH "/mnt"        
#define DEFAULT_PORTAL_FILENAME "portal.html"
#define DEFAULT_FAVICONICO_FILENAME "favicon.ico"

#define DEFAULT_HTTP_ACCESSLOG_FILENAME "access.log"
#define DEFAULT_HTTP_ERRORLOG_FILENAME "error.log"
#define DEFAULT_EXCPINFO_FILENAME "excep_bt.txt"

#define AUTH_SVR_NAME    "auth_svr"
#define AUTH_AGT_NAME    "auth_agt"

#ifndef CONF_HTTP_VERSION_11
#define CONF_HTTP_VERSION_11 "1.1"
#endif
#ifndef CONF_HTTP_VERSION_10
#define CONF_HTTP_VERSION_10 "1.0"
#endif
#ifndef DEFAULT_HTTP_VERSION_CONF
#define DEFAULT_HTTP_VERSION_CONF CONF_HTTP_VERSION_11
#endif

/*@}*/

/*@{*/
/** Defines for firewall rule sets. */
#define FWRULESET_GLOBAL "global"
#define FWRULESET_VALIDATING_USERS "validating-users"
#define FWRULESET_KNOWN_USERS "known-users"
#define FWRULESET_AUTH_IS_DOWN "auth-is-down"
#define FWRULESET_UNKNOWN_USERS "unknown-users"
#define FWRULESET_LOCKED_USERS "locked-users"
/*@}*/

/**
 * Mutex for the configuration file, used by the auth_servers related
 * functions. */
extern pthread_mutex_t config_mutex;

typedef enum {
    E_AUTH_CONN_INIT     = 0,
    E_AUTH_CONN_INACTIVE = 1,
    E_AUTH_CONN_ACTIVE   = 2,
} t_auth_conn_state;

typedef enum {
    E_NET_CONN_INIT     = 0,
    E_NET_CONN_INACTIVE = 1,
    E_NET_CONN_ACTIVE   = 2,
} t_internet_conn_state;

#define MAX_HTTP_CONTINUOUS_OFFLINE_CNT 3

/**
 * Information about the authentication server
 */
typedef struct _auth_serv_t {
    char* authserv_hostname;                      /**< @brief Hostname of the central server */
    char* authserv_hostip;                        /**< @brief IP of the central server */
    char* active_path;                            /**< @brief Path where path dir resides */
    char* passive_path;                           /**< @brief Path where path dir resides */
    char* authserv_seperator;                     /**< @brief seperator, default:"?" */
    char* authserv_check_script_path_fragment;    /**< @brief This is the script the user will be sent redirect to for check if not login.  */
    char* authserv_sms_script_path_fragment;      /**< @brief This is the script the user will be sent to for sms. */
    char* authserv_login_script_path_fragment;    /**< @brief This is the script the user will be sent to for login. */
    char* authserv_pass_script_path_fragment;  /**< @brief This is the script the user will be passed. */
    char* authserv_offline_script_path_fragment;  /**< @brief This is the script the user will be offline. */
    char* authserv_portal_script_path_fragment;   /**< @brief This is the script the user will be sent to after a successfull login. */
    char* authserv_update_portal_path_fragment;   /**< @brief This is the script the thread_portal_update will periodically check, coco. */
    char* authserv_dload_portal_path_fragment;    /**< @brief This is the script the thread_portal_update will download, kejin. */
#if 1 /* Now not used */
    char* authserv_msg_script_path_fragment;      /**< @brief This is the script the user will be sent to upon error to read a readable message. */
    char* authserv_ping_script_path_fragment;     /**< @brief This is the ping heartbeating script. */
    char* authserv_auth_script_path_fragment;     /**< @brief This is the script that talks the gateway protocol. */
#endif
    int authagent_tcp_port;                        /**< @brief TCP port the agent listens on */
    int authserv_http_port;                       /**< @brief Http port the central server/agent listens on */
    int authserv_ssl_port;                        /**< @brief Https port the central server listens on */
    int authserv_use_ssl;                         /**< @brief Use SSL or not */
    char *last_ip;                                /**< @brief Last ip used by authserver */
    t_auth_conn_state status;
    time_t last_online_time;
    time_t last_offline_time;
    time_t last_ctns_offline_time[MAX_HTTP_CONTINUOUS_OFFLINE_CNT];
    unsigned int offline_cnt;
    unsigned int ctns_offline_cnt;               /**< @brief continuous offline count of central server */
    unsigned int ctns_offline_cnt_sum;           /**< @brief continuous offline summary count of central server */
    int socket_fd;
    unsigned int echo_cnt;
    time_t last_echo_time;
    struct _auth_serv_mgmt_t* auth_server_mgmt;
    struct _auth_serv_t *next;
} t_auth_serv;

typedef struct _auth_serv_mgmt_t {
    struct _auth_serv_t *auth_server;
    char   name[MAX_AUTH_NAME_LEN];
}t_auth_serv_mgmt_t;

typedef struct _net_conn_mgmt_t {
    t_internet_conn_state net_status;
    time_t last_net_online_time;
    time_t last_net_offline_time;
    unsigned int offline_times;
}t_net_conn_mgmt_t;

/**
 * Firewall targets
 */
typedef enum {
    TARGET_DROP,
    TARGET_REJECT,
    TARGET_ACCEPT,
    TARGET_LOG,
    TARGET_ULOG
} t_firewall_target;

/**
 * Firewall rules
 */
typedef struct _firewall_rule_t {
    t_firewall_target target;   /**< @brief t_firewall_target */
    char *protocol;             /**< @brief tcp, udp, etc ... */
    char *port;                 /**< @brief Port to block/allow */
    char *mask;                 /**< @brief Mask for the rule *destination* */
    int mask_is_ipset; /**< @brief *destination* is ipset  */
    struct _firewall_rule_t *next;
} t_firewall_rule;

/**
 * Firewall rulesets
 */
typedef struct _firewall_ruleset_t {
    char *name;
    t_firewall_rule *rules;
    struct _firewall_ruleset_t *next;
} t_firewall_ruleset;

/**
 * Trusted MAC Addresses
 */
typedef struct _trusted_mac_t {
    char *mac;
    struct _trusted_mac_t *next;
} t_trusted_mac;

/**
 * Popular Servers
 */
typedef struct _popular_server_t {
    char *hostname;
    struct _popular_server_t *next;
} t_popular_server;

/**
 * Configuration structure
 */
typedef struct {
    char configfile[MAX_PATH_LEN];                   /**< @brief name of the config file */
    char htmlmsgfile[MAX_PATH_LEN];                  /**< @brief name of the HTML file used for messages */
    char wdctl_sock[MAX_PATH_LEN];                   /**< @brief wdctl path to socket */
    char internal_sock[MAX_PATH_LEN];                /**< @brief internal path to socket */                               
    char pidfile[MAX_PATH_LEN];                      /**< @brief pid file path of process */
    char external_interface[MAX_INTERFACE_NAME_LEN]; /**< @brief External network interface name for firewall rules */
    char external_address[MAX_IP_ADDR_LEN];          /**< @brief External IP address */
    char gw_id[MAX_GENERAL_LEN];                     /**< @brief ID of the Gateway, sent to central server */
    char gw_interface[MAX_IP_ADDR_LEN];              /**< @brief Interface we will accept connections on */
    char gw_address[MAX_IP_ADDR_LEN];                /**< @brief Internal IP address for our web server */
    char ssl_certs[MAX_GENERAL_LEN];                 /**< @brief Path to SSL certs for auth server verification */
    char ssl_cipher_list[MAX_GENERAL_LEN];           /**< @brief List of SSL ciphers allowed. Optional. */
    char httpdrealm[MAX_GENERAL_LEN];                /**< @brief HTTP Authentication realm */
    char httpdusername[MAX_GENERAL_LEN];             /**< @brief Username for HTTP authentication */
    char httpdpassword[MAX_GENERAL_LEN];             /**< @brief Password for HTTP authentication */
    char arp_table_path[MAX_PATH_LEN];               /**< @brief Path to custom ARP table, formatted like /proc/net/arp */
    char http_accesslog_file[MAX_PATH_LEN];
    char http_errorlog_file[MAX_PATH_LEN];
    char http_version[MAX_GENERAL_LEN];
    char place_code[MAX_GENERAL_LEN];
    char portal_code[MAX_GENERAL_LEN];
    char company[MAX_GENERAL_LEN];
    char ssid[MAX_GENERAL_LEN];
    char lessee_id[MAX_GENERAL_LEN];
    char portal_save_path[MAX_PATH_LEN];
    char favacon_ico_path[MAX_PATH_LEN];             /**< @brief favacon.ico save path */
    char semu_portal_ip[MAX_IP_ADDR_LEN];            /**< @brief boolean, whether to enable semu portal ip */
    char httpdname[MAX_GENERAL_LEN];                 /**< @brief Name the web server will return when replying to a request */
    char version[MAX_GENERAL_LEN];
    char dpi_bpf[MAX_GENERAL_LEN];                   /**< @brief DPI BPF filter */
    char dpi_log_file[MAX_PATH_LEN];
    t_net_conn_mgmt_t  net_conn;
    t_auth_serv_mgmt_t auth_servers;                       /**< @brief Auth servers list */
    t_auth_serv_mgmt_t auth_agents;                  /**< @brief Auth agents list */
    t_firewall_ruleset* rulesets;                    /**< @brief firewall rules */
    t_trusted_mac* trustedmaclist;                   /**< @brief list of trusted macs */
    t_popular_server* popular_servers;               /**< @brief list of popular servers */

    int gw_port;                                     /**< @brief Port the webserver will run on */
    int httpdmaxconn;                                /**< @brief Used by libhttpd, not sure what it does */
    int deltatraffic;                                /**< @brief reset each user's traffic (Outgoing and Incoming) value after each Auth operation. */
    int daemon;                                      /**< @brief if daemon > 0, use daemon mode */
    int external_web_port;                           /**< @brief Port the external service to serve letgo interface will run on */
    int max_client_num;                              /**< @brief Maximum client number a device can support */
    int clienttimeout;                               /**< @brief How many CheckIntervals before a client must be re-authenticated */
    int checkinterval;                               /**< @brief Frequency the the client timeout check thread will run. */
    int proxy_port;                                  /**< @brief Transparent proxy port (0 to disable) */
    int ssl_verify;                                  /**< @brief boolean, whether to enable auth server certificate verification */
    int ssl_use_sni;                                 /**< @brief boolean, whether to enable auth server for server name indication, the TLS extension */
#if USE_TCP_SOCK
    int tcp_sock;
#endif
    int company_id;
    int sms_flag;                                    /**< @brief boolean, whether to enable sms */
    int local_auth_flag;                             /**< @brief boolean, whether to enable local auth */
    int semu_flag;                                   /**< @brief boolean, whether to enable semu */
    int dpi_flag;                                    /**< @brief DPI function flag */
} T_CONFIG;

/** @brief Get the current gateway configuration */
T_CONFIG *config_get_config(void);

#if USE_TCP_SOCK
void config_set_tcpsock(int sock);
#endif

char* get_portal_version_string(void);
char* set_portal_version_string(char* newVersion);

void config_set_dpi(int start);

/** @brief Initialise the conf system */
void config_init(void);

/** @brief Initialize the variables we override with the command line*/
void config_init_override(void);

/** @brief Reads the configuration file */
void config_read(const char *filename);

/** @brief Check that the configuration is valid */
void config_validate(void);

/** @brief Get the active auth server */
t_auth_serv* get_auth_server(void);
t_auth_serv* get_auth_agent(void);
t_net_conn_mgmt_t* get_net_conn_mgmt(void);
t_auth_serv_mgmt_t* get_authsvr_mgmt(void);
t_auth_serv_mgmt_t* get_authagt_mgmt(void);

char* auth_conn_state2str(t_auth_conn_state state);
char* net_conn_state2str(t_internet_conn_state state);


/** @brief Bump server to bottom of the list */
void mark_auth_server_bad(t_auth_serv *);
void mark_auth_server_bad2(t_auth_serv *);


/** @brief Fetch a firewall rule set. */
t_firewall_rule *get_ruleset(const char *);

#define LOCK_CONFIG() do { \
    debug(LOG_DEBUG, "Locking config@func:%s", __func__); \
    pthread_mutex_lock(&config_mutex); \
    debug(LOG_DEBUG, "Config locked@func:%s", __func__); \
} while (0)

#define UNLOCK_CONFIG() do { \
    debug(LOG_DEBUG, "Unlocking config@func:%s", __func__); \
    pthread_mutex_unlock(&config_mutex); \
    debug(LOG_DEBUG, "Config unlocked@func:%s", __func__); \
} while (0)

#define LOCK_AUTH_SERVER() do { \
    debug(LOG_DEBUG, "Locking auth_srv@func:%s", __func__); \
    pthread_mutex_lock(&auth_srv_mutex); \
    debug(LOG_DEBUG, "auth_srv locked@func:%s", __func__); \
} while (0)

#define UNLOCK_AUTH_SERVER() do { \
    debug(LOG_DEBUG, "Unlocking auth_srv@func:%s", __func__); \
    pthread_mutex_unlock(&auth_srv_mutex); \
    debug(LOG_DEBUG, "auth_srv unlocked@func:%s", __func__); \
} while (0)

#define LOCK_AUTH_AGENT() do { \
    debug(LOG_DEBUG, "Locking auth_agt@func:%s", __func__); \
    pthread_mutex_lock(&auth_agt_mutex); \
    debug(LOG_DEBUG, "auth_agt locked@func:%s", __func__); \
} while (0)

#define UNLOCK_AUTH_AGENT() do { \
    debug(LOG_DEBUG, "Unlocking auth_agt@func:%s", __func__); \
    pthread_mutex_unlock(&auth_agt_mutex); \
    debug(LOG_DEBUG, "auth_agt unlocked@func:%s", __func__); \
} while (0)

#endif                          /* _CONFIG_H_ */
