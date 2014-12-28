/*
 * eax-test.c: test harness for EAX, common declarations
 */
/*
 * This file is Free Software.  It was originally written for secnet.
 * See README for full list of copyright holders.
 *
 * Copyright 2013 Ian Jackson
 * Copyright 2013 Mark Wooding
 *
 * You may redistribute secnet as a whole and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3, or (at your option) any
 * later version.
 *
 * You may redistribute this file and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later
 * version.
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


#ifndef EAX_TEST_H
#define EAX_TEST_H

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>

#define INFO                int dummy_info
#define I                   dummy_info
#define EAX_ENTRYPOINT_DECL /* empty */

#define EAX_DECLARATIONS_ONLY
#include "eax.c"
#undef EAX_DECLARATIONS_ONLY

void eaxtest_blockcipher_key_setup(const uint8_t *keydata, uint8_t bytes);

#define consttime_memeq(s1,s2,sz) (!memcmp((s1),(s2),(sz)))
    /* fine for running test vectors */

extern const size_t blocksize;

#define EAX_SOME_TEST						\
    const size_t blocksize = BLOCK_SIZE;			\
    static uint8_t INFO_B[BLOCK_SIZE], INFO_P[BLOCK_SIZE]

#endif /* EAX_TEST_H */
