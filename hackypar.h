/* Hacky parallelism
 * We fork, and return false !
 */
/*
 * This file is part of secnet.
 * See README for full list of copyright holders.
 *
 * secnet is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version d of the License, or
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

#ifndef hackympzpar_h
#define hackympzpar_h

struct site;

int hacky_par_start_failnow(void);
int hacky_par_mid_failnow(void);
void hacky_par_end(int *ok,
		   int32_t retries, int32_t timeout,
		   bool_t (*send_msg)(struct site *st), struct site *st);

#endif /* hackympzpar_h */
