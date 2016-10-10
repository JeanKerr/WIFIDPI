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
/** @file wdctl.h
    @brief monitoring client
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#ifndef _WDCTL_H_
#define _WDCTL_H_
#include "common.h"

#define DEFAULT_SOCK    "/tmp/wdctl.sock"

#define WDCTL_UNDEF      0
#define WDCTL_PASS       1
#define WDCTL_KICK       2
#define WDCTL_STATUS     3
#define WDCTL_STATISTICS 4
#define WDCTL_STOP       5
#define WDCTL_RESTART    6
#define WDCTL_DEBUG      7


#define WDCTL_MAX_BUF          MAX_BUF
#define WDCTL_MAX_PATH_LEN     256
#define WDCTL_MAX_PARAM_NUM    5
#define WDCTL_MAX_PARAM_LEN    20
#define WDCTL_MAX_CMD_LEN      16

typedef struct {
    char socket[WDCTL_MAX_PATH_LEN];
    int  command;
    char param[WDCTL_MAX_PARAM_NUM][WDCTL_MAX_PARAM_LEN];
} s_wdconfig;
#endif

