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
/** @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire
  @author Copyright (C) 2007 David Bird <david@coova.com>

 */
/* Note that libcs other than GLIBC also use this macro to enable vasprintf */
#include "common.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "httpd.h"

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
#include "client_list.h"
#include "centralserver.h"
#include "util.h"
#include "wd_util.h"

#include "simple_http.h"
#include "cJSON.h"
#include "../config.h"


/** The 404 handler is also responsible for redirecting to the auth server */
void http_callback_404(httpd* webserver, request* r, int error_code)
{
    int got_authdown_ruleset = (NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1);
    char tmp_url[MAX_BUF]={0};
    t_client* node=NULL;
    char* mac;
    T_CONFIG *pConfig = config_get_config();
    //t_auth_serv *auth_server = get_auth_server();
    /* 
     * XXX Note the code below assumes that the client's request is a plain
     * http request to a standard port. At any rate, this handler is called only
     * if the internet/auth server is down so it's not a huge loss, but still.
     */
    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
             httpdRequestHost(r), httpdRequestPath(r), r->request.query[0] ? "?" : "", r->request.query);
             
    if (!is_online())
    {
        char* buf;
        /* The internet connection is down at the moment  - apologize and do not redirect anywhere */
        safe_asprintf(&buf,
                      "<p>We apologize, but it seems that the internet connection that powers this hotspot is temporarily unavailable.</p>"
                      "<p>If at all possible, please notify the owners of this hotspot that the internet connection is out of service.</p>");

        http_send_page(webserver, r, "Uh oh! Internet access unavailable!", buf);
        free(buf);
        debug(LOG_INFO, "Sent %s an apology since I am not online - no point sending them to auth server", r->clientAddr);
    }
    else    
    {
        /* Re-direct them to auth server */
        //char *urlFragment;
        mac = arp_get(r->clientAddr);
        if (NULL == mac)
        {
            /* We could not get their MAC address */
            debug(LOG_INFO, "Failed to retrieve MAC address for ip %s, so not putting in the login request",
                 r->clientAddr);
            return;
        }
        else
        {
            debug(LOG_INFO, "Got client MAC address: %s for ip %s",  mac, r->clientAddr);
        }

        // if host is not in whitelist, maybe not in conf or domain'IP changed, it will go to here.
        debug(LOG_DEBUG, "Check host %s is in whitelist or not", r->request.host);       // e.g. www.example.com
        t_firewall_rule *rule;
        //e.g. example.com is in whitelist
        // if request http://www.example.com/, it's not equal example.com.
        for (rule = get_ruleset("global"); rule != NULL; rule = rule->next) {
            debug(LOG_DEBUG, "rule mask %s", rule->mask);
            if (strstr(r->request.host, rule->mask) == NULL) {
                debug(LOG_DEBUG, "host %s is not in %s, continue", r->request.host, rule->mask);
                continue;
            }
            int host_length = strlen(r->request.host);
            int mask_length = strlen(rule->mask);
            if (host_length != mask_length) {
                char prefix[1024] = { 0 };
                // must be *.example.com, if not have ".", maybe Phishing. e.g. phishingexample.com
                strncpy(prefix, r->request.host, host_length - mask_length - 1);        // e.g. www
                strcat(prefix, ".");    // www.
                strcat(prefix, rule->mask);     // www.example.com
                if (strcasecmp(r->request.host, prefix) == 0) {
                    debug(LOG_INFO, "allow subdomain");
                    fw_allow_host(r->request.host);
                    http_send_redirect(webserver, r, tmp_url, "allow subdomain");
                    free(mac);
                    return;
                }
            } else {
                /* e.g. "example.com" is in conf, so it had been parse to IP and added into "iptables allow"
                 *when process start. but then its' A record(IP) changed, it will go to here.*/
                debug(LOG_INFO, "allow domain again, because IP changed");
                fw_allow_host(r->request.host);
                http_send_redirect(webserver, r, tmp_url, "allow domain");
                free(mac);
                return;
            }
        }

        debug(LOG_DEBUG, "Get terminal type [%s] from [%s]", get_terminal_type(r->request.user_agent), r->request.user_agent);
        LOCK_CLIENT_LIST();
        if ((node = client_list_find(r->clientAddr, mac)) == NULL)
        {
            debug(LOG_DEBUG, "assign new client for %s", r->clientAddr);
            node = client_list_add(r->clientAddr, mac, NULL, get_terminal_type(r->request.user_agent), NULL, NULL);
        }
        else
        {
            debug(LOG_DEBUG, "http_callback_404 client %s is already in the client list", node->ip);
            client_update(node, NULL, get_terminal_type(r->request.user_agent), NULL, NULL, get_millisecond());
        }

        UNLOCK_CLIENT_LIST();
        free(mac);
        if(!node)
        {
            debug(LOG_WARNING, "Captured %s requesting [%s] but out of resource", r->clientAddr, tmp_url);
            http_send_page(webserver, r, "Error!", "Out of resource");
            return;
        }
        else
        {
            //url = httpdUrlEncode(tmp_url);
            debug(LOG_INFO, "Captured %s requesting [%s] and re-directing them to login page", r->clientAddr, tmp_url);
        }
        
        if(pConfig->local_auth_flag)
        {
            http_send_redirect_to_local_auth(webserver, r, NULL, "Redirect to login page");
        }
        else
        {
            http_send_redirect_to_center_auth(webserver, r, NULL, "Redirect to login page");
        }

        if(!got_authdown_ruleset)
        {
            bool isSrvOnline=is_auth_srvs_online();
            bool isAgtOnline=is_auth_agts_online();
            if (!isSrvOnline || !isAgtOnline)   
            {
                #if 0
                char* buf;
                /* The auth server is down at the moment - apologize and do not redirect anywhere */
                safe_asprintf(&buf,
                              "<p>We apologize, but it seems that we are currently unable to re-direct you to the login screen.</p>"
                              "<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>"
                              "<p>In a couple of minutes please <a href='%s'>click here</a> to try your request again.</p>", tmp_url);
        
                http_send_page(webserver, r, "Uh oh! Login screen unavailable!", buf);
                free(buf);
                #endif
                debug(LOG_WARNING, "%s not online while client %s access, directly allowed.", 
                                isSrvOnline?get_authsvr_mgmt()->name:get_authagt_mgmt()->name, r->clientAddr);
                LOCK_CLIENT_LIST();
                if(process_auth_result(webserver, r, node, AUTH_ALLOWED))
                {
                    if(!isSrvOnline)
                        inner_stt.loginByNoServer++;
                    else
                        inner_stt.loginByNoAgent++;
                }
                UNLOCK_CLIENT_LIST();
            }
        }
    }
}

void http_callback_wifidog(httpd* webserver, request* r)
{
    char title[MAX_TEMP_BUFFER_SIZE] = {0};
    char content[MAX_TEMP_BUFFER_SIZE]={0};
    
    snprintf(title, sizeof(title) - 1,"%s", config_get_config()->company);
    snprintf(content, sizeof(content) - 1,
        "Please use the menu to navigate the features of this %s installation.", config_get_config()->company);
    
    http_send_page(webserver, r, title, content);
}

void http_callback_about(httpd* webserver, request* r)
{
    char title[MAX_TEMP_BUFFER_SIZE] = {0};
    char content[MAX_TEMP_BUFFER_SIZE]={0};

    snprintf(title, sizeof(title) - 1,"About %s", config_get_config()->company);
    snprintf(content, sizeof(content) - 1,
        "This is %s'router version <strong> %s </strong>", config_get_config()->company, config_get_config()->version);

    http_send_page(webserver, r, title, content);
}

void http_callback_status(httpd* webserver, request* r)
{
    const T_CONFIG *config = config_get_config();
    char *status = NULL;
    char *buf;
    char title[MAX_TEMP_BUFFER_SIZE] = {0};

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Status page requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    status = get_status_text();
    safe_asprintf(&buf, "<pre>%s</pre>", status);
    snprintf(title, sizeof(title)-1, "%s's Router Status\n\n", config_get_config()->company);
    http_send_page(webserver, r, title, buf);
    free(buf);
    free(status);
}

void http_callback_statistics(httpd* webserver, request* r)
{
    const T_CONFIG *config = config_get_config();
    char *statistics = NULL;
    char *buf;
    char title[MAX_TEMP_BUFFER_SIZE] = {0};

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Statistics page requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    statistics = get_statistics_text();
    safe_asprintf(&buf, "<pre>%s</pre>", statistics);
    snprintf(title, sizeof(title)-1, "%s's Router Statistics\n\n", config_get_config()->company);
    http_send_page(webserver, r, title, buf);
    free(buf);
    free(statistics);
}

/** @brief Convenience function to redirect the web browser to the auth server
 * @param r The request
 * @param urlFragment The end of the auth server URL to redirect to (the part after path)
 * @param text The text to include in the redirect header ant the mnual redirect title */
void http_send_redirect_to_local_auth(httpd* server, request* r, const char* urlFragment, const char* text)
{
    char *protocol = NULL;
    int port = DEFAULT_AUTHSERVPORT;
    const T_CONFIG *config = config_get_config();
    
#ifdef USE_CYASSL
    t_auth_serv *auth_server = get_auth_server();
    if (auth_server->authserv_use_ssl) {
        protocol = "https";
        port = auth_server->authserv_ssl_port;
        
    } 
    else
#endif
    {
        protocol = "http";
        //port = auth_server->authserv_http_port;
        port = config->gw_port;  /* change to local portal port */
    }

    char *url = NULL;
    /* redirect to gw local portal file, eg:"http://192.168.1.1:8080/mnt/portal" */
    safe_asprintf(&url, "%s://%s:%d/%s",
                  protocol, config->gw_address, port, DEFAULT_PORTAL_FILENAME);
    http_send_redirect(server, r, url, text);
    free(url);
}

void http_send_redirect_to_center_auth(httpd* server, request* r, const char* urlFragment, const char* text)
{
    char *protocol = NULL;
    int port = DEFAULT_AUTHSERVPORT;
    const T_CONFIG *pConfig = config_get_config();
    const t_auth_serv *auth_server = get_auth_server();
    char* mac = NULL;
    char* url = NULL;
    //char ext_interface[MAX_INTERFACE_NAME_LEN]={0};
    //char ext_ip[MAX_IP_ADDR_LEN]={0};
    struct sockaddr_in me;

#ifdef USE_CYASSL
    if (auth_server->authserv_use_ssl) {
        protocol = "https";
        port = auth_server->authserv_ssl_port;
        
    } 
    else
#endif
    {
        protocol = "http";
        port = auth_server->authserv_http_port;
        //port = pConfig->gw_port;  /* change to local portal port */
    }
#if USE_TCP_SOCK
    socklen_t len = sizeof(struct sockaddr_in);
    if(-1 == pConfig->tcp_sock || -1 == getsockname(pConfig->tcp_sock, (struct sockaddr*)&me, &len)) 
    {
        debug(LOG_INFO, "Auth agt not connected yet...");
    }
#endif
    mac = arp_get2(r->clientAddr);
    if(NULL == mac) 
    {
        /* We could not get their MAC address */
        debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
        http_send_page(server, r, "Error!", "Failed to retrieve your MAC address");
        return;
    }

#if 0
    if (!IS_NULL_CONFIG(external_interface)) 
    {
        strncpy(ext_interface, pConfig->external_interface, MAX_INTERFACE_NAME_LEN-1);
    }
    else
    {
        get_ext_iface(ext_interface, MAX_INTERFACE_NAME_LEN);
    }

    if(!ext_interface[0])
        return;
    get_iface_ip2(ext_interface, ext_ip, sizeof(ext_ip));
#endif

    /* redirect to gw local portal file, eg:"http://192.168.1.1:8080/mnt/portal" */
    /* http://180.168.123.220:8088/WIFI_YUN/wifi/checkuser?user_mac=x&user_ip=y&place_code=z */
    safe_asprintf(&url, "%s://%s:%d%s%s%suser_mac=%s&user_ip=%s&place_code=%s&device_ip=%s&device_port=%d&type=%s&l=zh-cn&company=%d&sms_flag=%d&lessee_id=%s",
        protocol, auth_server->authserv_hostip?auth_server->authserv_hostip:auth_server->last_ip,
        port, auth_server->active_path, 
        auth_server->authserv_check_script_path_fragment, auth_server->authserv_seperator,
        mac, r->clientAddr, pConfig->place_code, 
        strcmp(ANY_IP_ADDR_STRING, inet_ntoa(me.sin_addr))?inet_ntoa(me.sin_addr):pConfig->external_address, ntohs(me.sin_port?me.sin_port:12345), get_terminal_type(r->request.user_agent),
        pConfig->company_id, pConfig->sms_flag, pConfig->lessee_id);
    
    http_send_redirect(server, r, url, text);
    if(url)  free(url);
    if(mac)  free(mac);
}

void http_send_redirect_to_auth(httpd* server, request* r, const char* urlFragment, const char* text)
{
#if 0
    char *protocol = NULL;
    int port = DEFAULT_AUTHSERVPORT;
    const T_CONFIG *pConfig = config_get_config();
    const t_auth_serv *auth_server = get_auth_server();
    char* url = NULL;
#ifdef USE_CYASSL
    t_auth_serv *auth_server = get_auth_server();
    if (auth_server->authserv_use_ssl) {
        protocol = "https";
        port = auth_server->authserv_ssl_port;
        
    } 
    else
#endif
    {
        protocol = "http";
        //port = auth_server->authserv_http_port;
        port = pConfig->gw_port;  /* change to local portal port */
    }

    safe_asprintf(&url, "%s://%s:%d%s%s",
                  protocol, pConfig->gw_address, port, auth_server->passive_path, urlFragment);

    http_send_redirect(server, r, url, text);
    free(url);
#endif
}


/** @brief Sends a redirect to the web browser 
 * @param r The request
 * @param url The url to redirect to
 * @param text The text to include in the redirect header and the manual redirect link title.  NULL is acceptable */
void http_send_redirect(httpd* server, request* r, const char* url, const char* text)
{
    char *message = NULL;
    char *header = NULL;
    char *response = NULL;
    /* Re-direct them to auth server */
    debug(LOG_DEBUG, "Redirecting client browser to %s", url);
    safe_asprintf(&header, "Location: %s", url);
    safe_asprintf(&response, "302 %s\n", text ? text : "Redirecting");
    httpdSetResponse(r, response);
    httpdAddHeader(r, header);
    free(response);
    free(header);
    safe_asprintf(&message, "Please <a href='%s'>click here</a>.", url);
    http_send_page(server, r, text ? text : "Redirection to message", message);
    free(message);
}

void http_send_portal_page(httpd* webserver, request* r)
{
    T_CONFIG *config = config_get_config();
    char *pBuffer;
    int ret;
    char file[MAX_PATH_LEN]={0};
    
    snprintf(file, sizeof(file)-1, "%s/%s", config->portal_save_path, DEFAULT_PORTAL_FILENAME);
    
    ret = httpdLoadFile2Buff(webserver, file, &pBuffer);
    if(ret<=0 || NULL==pBuffer)
    {
        debug(LOG_CRIT, "func:%s failed to _httpdLoadFile2Buff file:%s, ret:%d, pBuffer:%p", 
                         __func__, file, ret, pBuffer);
        return;
    }
    
    httpdSendFile(webserver, r, file);
    //httpdOutput(r, pBuffer);
    free(pBuffer);
    pBuffer=NULL;
    return;
}

void http_send_favicon_ico(httpd* webserver, request* r)
{
    T_CONFIG *config = config_get_config();
    char *pBuffer;
    int ret;
    char file[MAX_PATH_LEN]={0};
    
    snprintf(file, sizeof(file)-1, "%s/%s", config->favacon_ico_path, DEFAULT_FAVICONICO_FILENAME);
    
    ret = httpdLoadFile2Buff(webserver, file, &pBuffer);
    if(ret<=0 || NULL==pBuffer)
    {
        debug(LOG_CRIT, "func:%s failed to _httpdLoadFile2Buff file:%s, ret:%d, pBuffer:%p", 
                         __func__, file, ret, pBuffer);
        return;
    }
    
    httpdSendFile(webserver, r, file);
    free(pBuffer);
    pBuffer=NULL;
    return;
}


void http_send_page(httpd* webserver, request* r, const char* title, const char* message)
{
    T_CONFIG *config = config_get_config();
    char *pBuffer=NULL;
    int ret;
    
    ret = httpdLoadFile2Buff(webserver, config->htmlmsgfile, &pBuffer);
    if(ret<=0 || NULL==pBuffer)
    {
        debug(LOG_CRIT, "func:%s failed to _httpdLoadFile2Buff file:%s, ret:%d, pBuffer:%p", 
                         __func__, config->htmlmsgfile, ret, pBuffer);
        return;
    }
    
    httpdAddVariable(r, "title", title);
    httpdAddVariable(r, "message", message);
    httpdAddVariable(r, "rhyVersion", config->version);
    httpdAddVariable(r, "nodeID", config->place_code);
    httpdAddVariable(r, "company", config->company);
    
    httpdOutput(r, pBuffer);
    free(pBuffer);
    pBuffer=NULL;
    return;
}

void http_callback_smsquest(httpd* webserver, request* r)
{
    t_client* client=NULL;
    char* mac= NULL;
    char iface_ip[MAX_IP_ADDR_LEN]={0};
    char iface_mac[MAX_MAC_ADDR_LEN]={0};
    //httpVar* termimalType = httpdGetVariableByName(r, "type");
    httpVar* phone = httpdGetVariableByName(r, "phone");
    
    debug(LOG_DEBUG, "Entering http_callback_smsquest()");
    if(NULL != phone) 
    {
        /* They supplied variable "phone" */
        mac = arp_get(r->clientAddr);
        if(NULL == mac) 
        {
            /* We could not get their MAC address */
            debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
            http_send_page(webserver, r, "Sms Error!", "Failed to retrieve your MAC address");
            return;
        } 
        else
        {
            /* We have their MAC address */
            char request[MAX_BUF]={0};
            int sockfd;
            cJSON* pJson=NULL;
            char* ParseJsonOut=NULL;
            char ext_interface[MAX_INTERFACE_NAME_LEN]={0};
            const T_CONFIG* pConfig = config_get_config();
            t_auth_serv* auth_server = get_auth_server();
            char* pFound;
            char* res;
            char* JsonHead;

            sockfd = connect_auth_server();
            if (sockfd < 0) {
                free(mac);
                return;
            }
            /* send sms request */
            if(!IS_NULL_CONFIG(external_interface))
            {
                strncpy(ext_interface, pConfig->external_interface, MAX_INTERFACE_NAME_LEN-1);
            }
            else
            {
                get_ext_iface(ext_interface, MAX_INTERFACE_NAME_LEN);
            }
            
            if (ext_interface[0])
            {
                debug(LOG_ERR, "http_callback_smsquest failed to get ext_interface");
                free(mac);
                return;
            }
            get_iface_ip2(ext_interface, iface_ip, sizeof(iface_ip));
            get_iface_mac2(ext_interface, iface_mac, sizeof(iface_mac));
            snprintf(request, sizeof(request) - 1,
                "GET %s%s%suser_mac=%s&user_ip=%s&phone_tel=%s&user_type=%s"
                "&device_ip=%s&device_port=%s&device_mac=%s"
                "&ssid=%s&place_code=%s&portal_code=%s&company=%d&sms_flag=%d&lessee_id=%s HTTP/%s\r\n"
                "User-Agent: %s %s\r\n"
                "Host: %s\r\n"
                "\r\n",
                auth_server->passive_path, auth_server->authserv_sms_script_path_fragment, auth_server->authserv_seperator,
                mac, r->clientAddr, phone->value, get_terminal_type(r->request.user_agent),
                iface_ip, ext_interface, iface_mac,
                pConfig->ssid, pConfig->place_code, pConfig->portal_code, pConfig->company_id, 
                pConfig->sms_flag, pConfig->lessee_id,
                pConfig->http_version,
                pConfig->company, pConfig->version,  /*User-Agent*/
                (auth_server->authserv_hostip!=NULL) ? auth_server->authserv_hostip:auth_server->last_ip);
#ifdef USE_CYASSL
            if (auth_server->authserv_use_ssl) 
            {
                res = https_get(sockfd, request, auth_server->authserv_hostname);
            } 
            else
#endif
            {
                res = http_get2(sockfd, request, '}');
            }

            if (NULL == res || NULL == (JsonHead=strchr(res, '{'))) 
            {
                debug(LOG_ERR, "There was a problem with update response from the portal server!");
                free(mac);
                return;
            } 
            
            /* Utilize cJSON lib to parse version string, coco. *
            * Response contains placecode and version. 		 *
            * res string format example:									*
            * "[\n {\n \"placecode\": \"200\",\n \"version\": \"1.0\",\n \"remark01\": \" \",\n \"remark02\": \" \",\n \"remark03\": \" \",\n \"remark04\": \" \",\n \"remark05\": \" \"\n }\n ]"; */
                
            debug(LOG_DEBUG, "http_callback_smsquest get correct response:\n%s\n", JsonHead);
            pJson = cJSON_Parse(JsonHead);
            if (!pJson) 
            {
                debug(LOG_ERR, "http_callback_smsquest JSON Parse Error before:\n%s\n",cJSON_GetErrorPtr());
            }
            else
            {
                char code[MAX_GENERAL_LEN]={0};
                char msg[MAX_GENERAL_LEN]={0};
                char record_id[MAX_GENERAL_LEN]={0};
                char identify_code[MAX_GENERAL_LEN]={0};
                char phone_tel[MAX_GENERAL_LEN]={0};
                ParseJsonOut = cJSON_Print(pJson);
                debug(LOG_DEBUG, "ParseJsonOut: %s", ParseJsonOut);
                pFound = cJSON_FindStrNStrValue(pJson, "code", code, sizeof(code)-1);
                if(pFound)
                {
                    cJSON_FindStrNStrValue(pJson, "record_id", record_id, sizeof(record_id)-1);
                    cJSON_FindStrNStrValue(pJson, "identify_code", identify_code, sizeof(identify_code)-1);
                    cJSON_FindStrNStrValue(pJson, "phone_tel", phone_tel, sizeof(phone_tel)-1);
                }
                pFound = cJSON_FindStrNStrValue(pJson, "msg", msg, sizeof(msg)-1);
                cJSON_Delete(pJson);
                free(ParseJsonOut);
                free(res);
                if((0==strncmp(code, "200", sizeof(code)-1)) && (0==strncmp(msg, "SUCCESS", sizeof(msg)-1)))
                {
                    LOCK_CLIENT_LIST();
                    if ((client = client_list_find(r->clientAddr, mac)) == NULL)
                    {
                        debug(LOG_DEBUG, "assign new client for %s", r->clientAddr);
                        client = client_list_add(r->clientAddr, mac, phone->value, get_terminal_type(r->request.user_agent), record_id, identify_code);
                    }
                    else
                    {
                        debug(LOG_DEBUG, "http_callback_smsquest client %s is already in the client list", client->ip);
                        client_update(client, phone->value, get_terminal_type(r->request.user_agent), record_id, identify_code, 0);
                    }
                    UNLOCK_CLIENT_LIST();
                }
                else
                {
                    free(mac);
                    debug(LOG_DEBUG, "client %s smsQuest fail, code:%s, msg:%s", r->clientAddr, code, msg);
                    http_send_page(webserver, r, code, msg);
                    return;
                }
            }
        }
        free(mac);
        return;
    } 

    /* They did not supply variable "phone" */
    debug(LOG_DEBUG, "http_callback_smsquest() cannot get phone number");
    http_send_page(webserver, r, "Sms Error!", "Invalid phone number");
}

/* TODO: use http_callback_auth to replace */
void http_callback_checklogin(httpd* webserver, request* r)
{
    t_client *client;
    httpVar *token;
    char *mac;

    debug(LOG_DEBUG, "Entering http_callback_checklogin()");
    if ((token = httpdGetVariableByName(r, "token")))
    {
        /* They supplied variable "token" */
        mac = arp_get(r->clientAddr);
        if(NULL == mac)
        {
            /* We could not get their MAC address */
            debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
            http_send_page(webserver, r, "Login Error!", "Failed to retrieve your MAC address");
            return;
        }
        
        if ((client = client_list_find(r->clientAddr, mac)) == NULL)
        {
            debug(LOG_ERR, "Failed to retrieve client[IP:%s, MAC:%s] infomation, maybe it was timedout", r->clientAddr, mac);
            http_send_portal_page(webserver, r);
            free(mac);
            return;
        } 
        
        {
            /* We have their MAC address */
            char request[MAX_BUF]={0};
            int sockfd;
            cJSON* pJson=NULL;
            char* ParseJsonOut=NULL;
            const T_CONFIG *pConfig = config_get_config();
            t_auth_serv *auth_server = get_auth_server();
            char* pFound=NULL;
            char* res=NULL;
            char* JsonHead=NULL;
            
            sockfd = connect_auth_server();
            if (sockfd < 0)
            {
                free(mac);
                return;
            }
            /* send login request */
            snprintf(request, sizeof(request) - 1,
                "GET %s%s%sphone_tel=%s&record_id=%s&user_mac=%s&identity_code=%s&company=%d HTTP/%s\r\n"
                "User-Agent: %s %s\r\n"
                "Host: %s\r\n"
                "\r\n",
                auth_server->passive_path, auth_server->authserv_login_script_path_fragment, auth_server->authserv_seperator,
                client->phone, client->record_id, mac, client->token, pConfig->company_id,
                pConfig->http_version,
                pConfig->company, pConfig->version, 
                (auth_server->authserv_hostip!=NULL) ? auth_server->authserv_hostip:auth_server->last_ip);
            #ifdef USE_CYASSL
            if (auth_server->authserv_use_ssl) 
            {
                res = https_get(sockfd, request, auth_server->authserv_hostname);
            } 
            else
            #endif
            {
                res = http_get2(sockfd, request, '}');
            }
            
            if (NULL == res || NULL == (JsonHead=strchr(res, '{'))) 
            {
                debug(LOG_ERR, "There was a problem with update response from the portal server!");
                free(mac);
                if(res) 
                free(res);
                return;
            } 
            
            /* Utilize cJSON lib to parse version string, coco. *
            * Response contains placecode and version. 		 *
            * res string format example:									*
            * "[\n {\n \"placecode\": \"200\",\n \"version\": \"1.0\",\n \"remark01\": \" \",\n \"remark02\": \" \",\n \"remark03\": \" \",\n \"remark04\": \" \",\n \"remark05\": \" \"\n }\n ]"; */
            
            debug(LOG_DEBUG, "http_callback_checklogin get correct response:\n%s\n", JsonHead);
            pJson = cJSON_Parse(JsonHead);
            if (!pJson) 
            {
                debug(LOG_ERR, "http_callback_checklogin JSON Parse Error before:\n%s\n", cJSON_GetErrorPtr());
            }
            else
            {
                char jsonRetCode[MAX_GENERAL_LEN]={0};
                char jsonRetMsg[MAX_GENERAL_LEN]={0};
                char record_id[MAX_GENERAL_LEN]={0};
                char redirect_url[MAX_GENERAL_LEN]={0};
                t_authcode authCode = AUTH_ERROR;
                ParseJsonOut = cJSON_Print(pJson);
                debug(LOG_DEBUG, "ParseJsonOut: %s", ParseJsonOut);
                pFound = cJSON_FindStrNStrValue(pJson, "code", jsonRetCode, sizeof(jsonRetCode)-1);
                if(pFound)
                {
                    cJSON_FindStrNStrValue(pJson, "record_id", record_id, sizeof(record_id)-1);
                    cJSON_FindStrNStrValue(pJson, "url", redirect_url, sizeof(redirect_url)-1);
                }
                pFound = cJSON_FindStrNStrValue(pJson, "msg", jsonRetMsg, sizeof(jsonRetMsg)-1);
                cJSON_Delete(pJson);
                free(ParseJsonOut);
                if((0==strncmp(jsonRetCode, "200", sizeof(jsonRetCode)-1)) && (0==strncmp(jsonRetMsg, "SUCCESS", sizeof(jsonRetMsg)-1)))
                {
                    authCode = AUTH_ALLOWED;
                }
                #if 0
                else 
                {
                    //if((0==strncmp(code, "202", sizeof(code)-1)) && (0==strncmp(msg, "PARAMETER ERROR", sizeof(msg)-1)))
                    /* token error */
                    //code=AUTH_ERROR;
                }
                #endif
                LOCK_CLIENT_LIST();
                client = client_list_find(r->clientAddr, mac);
                if(client)
                {
                    process_auth_result(webserver, r, client, authCode);
                }
                UNLOCK_CLIENT_LIST();
                if(!client)
                {
                    debug(LOG_ERR, "Failed to retrieve client[IP:%s, MAC:%s] infomation, maybe it was timedout", r->clientAddr, mac);
                    http_send_portal_page(webserver, r);
                }
            }
            free(res);
        }
        free(mac);
        return;
    } 
    /* They did not supply variable "token" */
    http_send_page(webserver, r, "Login Error!", "Invalid token");
}

void http_callback_pass(httpd* webserver, request* r)
{
    bool pro_success=false;
    unsigned long long pass_time=0;
    cJSON* root=NULL;
    char rspmsg[MAX_TEMP_BUFFER_SIZE]={0};
    char* ParseJsonOut;
    t_client *client=NULL;
    char *mac=NULL;
    char *mac2=NULL;
    httpVar* getmac = httpdGetVariableByName(r, "user_mac");
    httpVar* ip = httpdGetVariableByName(r, "user_ip");
    httpVar* phone = httpdGetVariableByName(r, "phone_tel");
    httpVar* record = httpdGetVariableByName(r, "record_id");
    //httpVar* device_ip = httpdGetVariableByName(r, "device_ip");
    httpVar* is_release = httpdGetVariableByName(r, "is_release");
    httpVar* identify_code = httpdGetVariableByName(r, "identify_code");
    //httpVar* place_code = httpdGetVariableByName(r, "place_code");

    debug(LOG_DEBUG, "Entering http_callback_pass()");
    if(NULL != ip && NULL != getmac && NULL != phone && NULL != record && NULL != is_release && NULL != identify_code)
    {
        /* They supplied variable "token" */
        mac = arp_get(ip->value);
        mac2 = arp_get2(ip->value);
        if(NULL == mac || NULL == mac2)
        {
            /* We could not get their MAC address */
            debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", ip->value);
            goto FAIL;
        }
        if(0 != strcmp(mac2, getmac->value))
        {
            /* We could not get their MAC address */
            debug(LOG_ERR, "Retrieve error MAC address %s, but real mac %s", getmac->value, mac2);
            goto FAIL;
        }
        
        if(0 != strcmp("1", is_release->value))/* 0: send sms */
        {
            goto FAIL;
        }
        
        LOCK_CLIENT_LIST();
        if ((client = client_list_find(ip->value, mac)) == NULL)
        {
            debug(LOG_DEBUG, "http_callback_pass new client %s", ip->value);
            client = client_list_add(ip->value, mac, phone->value, get_terminal_type(r->request.user_agent), record->value, identify_code->value);
        }
        else
        {
            debug(LOG_DEBUG, "http_callback_pass client %s is already in the client list", client->ip);
            client_update(client, phone->value, get_terminal_type(r->request.user_agent), record->value, identify_code->value, get_millisecond());
        }
        if(!client)
        {
            UNLOCK_CLIENT_LIST();
            goto FAIL;
        }
        pass_time = client->pass_time;
        if(process_auth_result(webserver, r, client, AUTH_ALLOWED))
            inner_stt.loginByAuthServer++;
        UNLOCK_CLIENT_LIST();
        
        pro_success = true;
        root=cJSON_CreateObject();
        cJSON_AddItemToObject(root, "code", cJSON_CreateString("200"));
        memset(rspmsg, 0, sizeof(rspmsg));
        snprintf(rspmsg, sizeof(rspmsg)-1, "%s is passed", phone->value);
        cJSON_AddItemToObject(root, "msg", cJSON_CreateString(rspmsg));
        memset(rspmsg, 0, sizeof(rspmsg));
        snprintf(rspmsg, sizeof(rspmsg)-1, "%llu", pass_time);
        cJSON_AddItemToObject(root, "pass_time", cJSON_CreateString(rspmsg));
    }

FAIL:
    if(mac) free(mac);
    if(mac2) free(mac2);
    if(!pro_success)
    {
        root=cJSON_CreateObject();
        cJSON_AddItemToObject(root, "code", cJSON_CreateString("201"));
        memset(rspmsg, 0, sizeof(rspmsg));
        snprintf(rspmsg, sizeof(rspmsg)-1, "%s passed error", phone?phone->value:"null phone_tel");
        cJSON_AddItemToObject(root, "msg", cJSON_CreateString(rspmsg));
        memset(rspmsg, 0, sizeof(rspmsg));
        snprintf(rspmsg, sizeof(rspmsg)-1, "%llu", get_millisecond());
        cJSON_AddItemToObject(root, "pass_time", cJSON_CreateString(rspmsg));
    }
    
    ParseJsonOut = cJSON_Print(root);
    cJSON_Delete(root);
    debug(LOG_DEBUG, "ParseJsonOut: %s", ParseJsonOut);
    
    httpdSetResponse(r, "200\n");
    httpdOutput(r, ParseJsonOut);
        
    if(ParseJsonOut)
        free(ParseJsonOut);
    return;
}

void http_callback_offline(httpd* webserver, request* r)
{
    t_client *client=NULL;
    char *mac;
    httpVar* getmac = httpdGetVariableByName(r, "user_mac");
    httpVar* phone = httpdGetVariableByName(r, "phone_tel");
    httpVar* record = httpdGetVariableByName(r, "record_id");
    httpVar* pass_time = httpdGetVariableByName(r, "pass_time");
    httpVar* off_time = httpdGetVariableByName(r, "off_time");
    httpVar* company_id = httpdGetVariableByName(r, "company");
    
    debug(LOG_DEBUG, "Entering http_callback_offline()");
    if(NULL != getmac && NULL != phone && NULL != record && NULL != pass_time && NULL != off_time && NULL != company_id)
    {
        mac = wd_convertmac(getmac->value);
        LOCK_CLIENT_LIST();
        client = client_list_find_by_mac(mac);
        if(NULL == client)
        {
            UNLOCK_CLIENT_LIST();
            debug(LOG_NOTICE, "Retrieve client failed, maybe client [%s] is already offline", mac);
            free(mac);
            return;
        }

        if((0 != strcmp(client->phone, phone->value)) || (0 != strcmp(client->record_id, record->value)))
        {
            debug(LOG_WARNING, "Client info differs, local phone:%s,record_id:%s, remote[%s,%s]", 
                client->phone, client->record_id, phone->value, record->value);
        }
        
        debug(LOG_INFO, "Logout a client: [IP:%s, MAC:%s, Phone:%s, Token:%s, Record:%s]", 
                        client->ip, client->mac, client->phone, client->token, client->record_id);
        if(logout_client(client, false))
            inner_stt.logoutByAuthServer++;
        UNLOCK_CLIENT_LIST();

        free(mac);
    }

    return;
}

void http_callback_auth(httpd* webserver, request* r)
{
    t_client *client;
    httpVar *token;
    char *mac;

    if ((token = httpdGetVariableByName(r, "token"))) 
    {
        /* They supplied variable "token" */
        if (!(mac = arp_get(r->clientAddr))) {
            /* We could not get their MAC address */
            debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
            http_send_page(webserver, r, "Auth Error!", "Failed to retrieve your MAC address");
        }
        else
        {
            /* We have their MAC address */
            LOCK_CLIENT_LIST();
            if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
                debug(LOG_DEBUG, "New client for %s", r->clientAddr);
                client = client_list_add(r->clientAddr, mac, NULL, get_terminal_type(r->request.user_agent), NULL, token->value);
                if(!client)
                {
                    debug(LOG_WARNING, "Out of resource for ip %s", r->clientAddr);
                    http_send_page(webserver, r, "Auth Error!", "Out of resource");
                }
            } 
            else
            {
                debug(LOG_DEBUG, "Client for %s is already in the client list", client->ip);
            }
    
            UNLOCK_CLIENT_LIST();
            /* applies for case 1 and 3 from above if */
            authenticate_client(webserver, r);
            free(mac);
        }
    }
    else 
    {
        /* They did not supply variable "token" */
        http_send_page(webserver, r, "Auth Error!", "Invalid token");
    }
}

void http_callback_disconnect(httpd* webserver, request* r)
{
    const T_CONFIG *config = config_get_config();
    /* XXX How do you change the status code for the response?? */
    httpVar *token = httpdGetVariableByName(r, "token");
    httpVar *mac = httpdGetVariableByName(r, "mac");

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Disconnect requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    if (token && mac) 
    {
        t_client *client;
        LOCK_CLIENT_LIST();
        client = client_list_find_by_mac(mac->value);
        if (!client || strcmp(client->token, token->value))
        {
            UNLOCK_CLIENT_LIST();
            debug(LOG_INFO, "Disconnect %s with incorrect token %s", mac->value, token->value);
            httpdOutput(r, "Invalid token for MAC");
            return;
        }
        if(logout_client(client, true))
            inner_stt.logoutByTerminal++;
        UNLOCK_CLIENT_LIST();
    }
    else
    {
        debug(LOG_INFO, "Disconnect called without both token and MAC given");
        httpdOutput(r, "Both the token and MAC need to be specified");
    }
    return;
}

bool tcp_callback_pass(char* data, unsigned int lenth, tcp_request* r)
{
    bool pro_success=false;
    unsigned long long pass_time=0;
    cJSON* root=NULL;
    char rspmsg[MAX_TEMP_BUFFER_SIZE]={0};
    char* ParseJsonOut;
    t_client *client=NULL;
    char *mac=NULL;
    char *mac2=NULL;
    tcpVar* getmac = tcpGetVariableByName(r, "user_mac");
    tcpVar* ip = tcpGetVariableByName(r, "user_ip");
    tcpVar* phone = tcpGetVariableByName(r, "phone_tel");
    tcpVar* record = tcpGetVariableByName(r, "record_id");
    //tcpVar* device_ip = tcpGetVariableByName(r, "device_ip");
    tcpVar* is_release = tcpGetVariableByName(r, "is_release");
    tcpVar* identify_code = tcpGetVariableByName(r, "identify_code");
    //tcpVar* place_code = tcpGetVariableByName(r, "place_code");

    debug(LOG_DEBUG, "Entering tcp_callback_pass()");
    if(NULL != ip && NULL != getmac && NULL != phone && NULL != record && NULL != is_release && NULL != identify_code)
    {
        /* They supplied variable "token" */
        mac = arp_get(ip->value);
        mac2 = arp_get2(ip->value);
        if(NULL == mac || NULL == mac2)
        {
            /* We could not get their MAC address */
            debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", ip->value);
            goto FAIL;
        }
        if(0 != strcmp(mac2, getmac->value))
        {
            /* We could not get their MAC address */
            debug(LOG_ERR, "Retrieve error MAC address %s, but real mac %s", getmac->value, mac2);
            goto FAIL;
        }
        
        if(0 != strcmp("1", is_release->value))/* 0: send sms */
        {
            goto FAIL;
        }
        
        LOCK_CLIENT_LIST();
        if ((client = client_list_find(ip->value, mac)) == NULL)
        {
            debug(LOG_DEBUG, "tcp_callback_pass new client %s", ip->value);
            client = client_list_add(ip->value, mac, phone->value, get_terminal_type(NULL), record->value, identify_code->value);
        }
        else
        {
            debug(LOG_DEBUG, "http_callback_pass client %s is already in the client list", client->ip);
            client_update(client, phone->value, get_terminal_type(NULL), record->value, identify_code->value, get_millisecond());
        }
        if(!client)
        {
            UNLOCK_CLIENT_LIST();
            goto FAIL;
        }
        pass_time = client->pass_time;
        if(process_auth_result(NULL, NULL, client, AUTH_ALLOWED))
            inner_stt.loginByAuthAgent++;
        UNLOCK_CLIENT_LIST();
        
        pro_success = true;
        root=cJSON_CreateObject();
        cJSON_AddItemToObject(root, "code", cJSON_CreateString("200"));
        memset(rspmsg, 0, sizeof(rspmsg));
        snprintf(rspmsg, sizeof(rspmsg)-1, "%s is passed", phone->value);
        cJSON_AddItemToObject(root, "msg", cJSON_CreateString(rspmsg));
        memset(rspmsg, 0, sizeof(rspmsg));
        snprintf(rspmsg, sizeof(rspmsg)-1, "%llu", pass_time);
        cJSON_AddItemToObject(root, "pass_time", cJSON_CreateString(rspmsg));
    }

FAIL:
    if(mac) free(mac);
    if(mac2) free(mac2);
    if(!pro_success)
    {
        root=cJSON_CreateObject();
        cJSON_AddItemToObject(root, "code", cJSON_CreateString("201"));
        memset(rspmsg, 0, sizeof(rspmsg));
        snprintf(rspmsg, sizeof(rspmsg)-1, "%s passed error", phone?phone->value:"null phone_tel");
        cJSON_AddItemToObject(root, "msg", cJSON_CreateString(rspmsg));
        memset(rspmsg, 0, sizeof(rspmsg));
        snprintf(rspmsg, sizeof(rspmsg)-1, "%llu", get_millisecond());
        cJSON_AddItemToObject(root, "pass_time", cJSON_CreateString(rspmsg));
    }
    ParseJsonOut = cJSON_Print(root);
    cJSON_Delete(root);
    debug(LOG_DEBUG, "ParseJsonOut: %s", ParseJsonOut);
    
    tcpSetResponseHead(r, &r->head);
    tcpSetResponseData(r, ParseJsonOut, strlen(ParseJsonOut));
    tcpOutputResponse(r);
        
    if(ParseJsonOut)
        free(ParseJsonOut);
    return pro_success;
}

bool tcp_callback_echo(char* data, unsigned int lenth, tcp_request* r)
{
    //LOCK_CONFIG();
    t_auth_serv* auth_agt=find_auth_agt_by_socket(r->sock);
    //UNLOCK_CONFIG();
    
    if(auth_agt)
    {
        auth_agt->echo_cnt++;       //no lock, dont care the accurate correction
        time(&auth_agt->last_echo_time);
    }
    
    tcpSetResponseHead(r, &r->head);
    tcpSetResponseData(r, data, lenth);
    tcpOutputResponse(r);

    return TRUE;
}

