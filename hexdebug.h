/* This file is Free Software.  It was written for secnet.
 *
 * Authored 2013      Ian Jackson
 *
 * You may redistribute this file freely - the copyrightholders and
 * authors declare that they wish these files to be in the public
 * domain; or alternatively (at your option) that you may deal with
 * them according to the `CC0 1.0 Universal' licence.
 *
 * You may redistribute secnet as a whole and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3, or (at your option) any
 * later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, see
 * https://www.gnu.org/licenses/gpl.html.
 */

#ifndef HEXDEBUG_H
#define HEXDEBUG_H

#include <stdio.h>
#include <sys/types.h>

static inline void hexdebug(FILE *file, const void *buffer, size_t len)
{
    const uint8_t *array=buffer;
    size_t i;
    for (i=0; i<len; i++)
	fprintf(file,"%02x",array[i]);
}

#endif /*HEXDEBUG_H*/
