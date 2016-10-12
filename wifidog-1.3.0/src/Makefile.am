#
# $Id$
#

noinst_LIBRARIES = libgateway.a

bin_PROGRAMS = wifidog \
	wdctl
 
AM_CPPFLAGS = \
	-I${top_srcdir}/libhttpd/ \
	-I${top_srcdir}/libdpid/include/ \
	-DSYSCONFDIR='"$(sysconfdir)"' \
	-Wall \
	-Wextra \
	-Wno-unused-parameter
wifidog_LDADD = libgateway.a $(top_builddir)/libhttpd/libhttpd.la $(top_builddir)/libdpid/lib/libndpi.la

wifidog_SOURCES = main.c ndpi_util.c ndpiReader.c

libgateway_a_SOURCES = commandline.c \
	conf.c \
	debug.c \
	fw_iptables.c \
	firewall.c \
	gateway.c \
	centralserver.c \
	http.c \
	auth.c \
	client_list.c \
	util.c \
	wdctl_thread.c \
	agent_thread.c \
	portal_thread.c \
        dpi_thread.c \
	safe.c \
	httpd_thread.c \
	simple_http.c \
	pstring.c \
	wd_util.c \
	cJSON.c

noinst_HEADERS = commandline.h \
	common.h \
	conf.h \
	debug.h \
	fw_iptables.h \
	firewall.h \
	gateway.h \
	centralserver.h \
	http.h \
	auth.h \
	client_list.h \
	util.h \
	wdctl_thread.h \
	wdctl.h \
	agent_thread.h \
	portal_thread.h \
        dpi_thread.h 
	safe.h \
	httpd_thread.h \
	simple_http.h \
	pstring.h \
	wd_util.h \
	cJSON.h \
	ndpi_util.h

wdctl_LDADD = libgateway.a

wdctl_SOURCES = wdctl.c
