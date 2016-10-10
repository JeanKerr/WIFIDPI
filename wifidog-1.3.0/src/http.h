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
/** @file http.h
    @brief HTTP IO functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _HTTP_H_
#define _HTTP_H_

#include "httpd.h"

/**@brief Callback for libhttpd, main entry point for captive portal */
void http_callback_404(httpd *, request *, int);
/**@brief Callback for libhttpd */
void http_callback_wifidog(httpd *, request *);
/**@brief Callback for libhttpd */
void http_callback_about(httpd *, request *);
/**@brief Callback for libhttpd */
void http_callback_status(httpd *, request *);

/**@brief Callback for libhttpd */
void http_callback_statistics(httpd* webserver, request* r);

/**@brief Callback for sending portal page */
void http_send_portal_page(httpd *, request *);

/**@brief Callback for sending favicon ico file */
void http_send_favicon_ico(httpd *, request *);

/** @brief Sends a HTML page to web browser */
void http_send_page(httpd *, request *, const char *, const char *);

/**@brief Callback for sms request */
void http_callback_smsquest(httpd *, request *);

/**@brief Callback for login */
void http_callback_checklogin(httpd *, request *);

/**@brief Auth server notify interface for letting client pass */
void http_callback_pass(httpd *, request *);

/**@brief Auth server notify interface for letting client off */
void http_callback_offline(httpd *, request *);

/**@brief Callback for libhttpd, main entry point post login for auth confirmation */
void http_callback_auth(httpd *, request *);

/**@brief Callback for libhttpd, disconnect user from network */
void http_callback_disconnect(httpd *, request *);

/** @brief Sends a redirect to the web browser */
void http_send_redirect(httpd *,  request *, const char *, const char *);
/** @brief Convenience function to redirect the web browser to the auth server */
void http_send_redirect_to_local_auth(httpd *, request *, const char *, const char *);
/** @brief Convenience function to redirect the web browser to the center auth server */
void http_send_redirect_to_center_auth(httpd *, request *, const char *, const char *);
/** @brief Convenience function to redirect the web browser to the center auth server */
void http_send_redirect_to_auth(httpd *, request *, const char *, const char *);

bool tcp_callback_pass(char* data, unsigned int lenth, tcp_request* r);

bool tcp_callback_echo(char* data, unsigned int lenth, tcp_request* r);

bool tcp_callback_register_resp(char* data, unsigned int lenth, tcp_request* r);

#endif /* _HTTP_H_ */

