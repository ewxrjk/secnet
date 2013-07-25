/*
 * eax-serpent-test.c: test harness glue for EAX-Serpent
 */
/*
 * This file is Free Software.  It was originally written for secnet.
 *
 * You may redistribute it and/or modify it under the terms of the GNU
 * General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
