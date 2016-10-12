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
/** @file portal_thread.h
    @brief portal update thread
    @author Copyright (C) 2016 Jean.Kerr <coco.ke@ruhaoyi.com>
*/

#ifndef _DPI_THREAD_H_
#define _DPI_THREAD_H_

#define MAX_PORTNAME_LEN 64

typedef struct
{
	char portName[MAX_INTERFACE_NAME_LEN];
	char bpfFilter[MAX_GENERAL_LEN];
	char logPath[MAX_PATH_LEN];
	int  dpiFlag;
}T_DPI_PARAM;


/** @brief thread for dpi processing. */
void thread_comm_dpi(void *arg);


#endif
