/*
 * eax-serpent-test.c: test harness glue for EAX-Serpent
 */
/*
 * This file is Free Software.  It was originally written for secnet.
 *
 * Copyright 2013 Ian Jackson
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
/*
 * The corresponding test vector files are eax-serpent-test.vectors
 * and eax-serpentbe-test.vectors.  eax-serpent-test.vectors was
 * provided by Mark Wooding and eax-serpentbe-test.vectors was
 * generated by this file (in its guise as eax-serpentbe-test).  I
 * don't believe these test vecctors are creative works that attract
 * copyright.  -iwj.
 */

#include "eax-test.h"
#include "serpent.h"

#define BLOCK_SIZE 16
static struct keyInstance key;

EAX_SOME_TEST;

void eaxtest_blockcipher_key_setup(const uint8_t *keydata, uint8_t bytes)
{
    serpent_makekey(&key, bytes*8, keydata);
}

static void BLOCK_ENCRYPT(uint8_t dst[BLOCK_SIZE],
			  const uint8_t src[BLOCK_SIZE])
{
    serpent_encrypt(&key, src, dst);
}

#include "eax.c"
