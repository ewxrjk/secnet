/*
 * eax-aes-test.c: test harness glue for EAX-AES (EAX-Rijndael)
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
#include "aes.h"

#define BLOCK_SIZE AES_BLOCK_SIZE
static AES_KEY key;

EAX_SOME_TEST;

void eaxtest_blockcipher_key_setup(const uint8_t *keydata, uint8_t bytes)
{
    AES_set_encrypt_key(keydata, bytes*8, &key);
}

static void BLOCK_ENCRYPT(uint8_t dst[BLOCK_SIZE],
			  const uint8_t src[BLOCK_SIZE])
{
    AES_encrypt((const void*)src, (void*)dst, &key);
}

#include "eax.c"
