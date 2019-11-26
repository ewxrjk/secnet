/*
 * osdep.c
 * - portability routines
 */
/*
 * This file is part of secnet.
 * See README for full list of copyright holders.
 *
 * secnet is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * secnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * version 3 along with secnet; if not, see
 * https://www.gnu.org/licenses/gpl.html.
 */

#ifndef osdep_h
#define osdep_h

#include "config.h"

#include <stdio.h>

#ifndef HAVE_FMEMOPEN
extern FILE *fmemopen(void *buf, size_t size, const char *mode);
#endif

#endif /* osdep_h */
