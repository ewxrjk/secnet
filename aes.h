/*
 * aes.h - Header file declaring AES functions.
 */
/*
 * This file is Free Software.  It has been modified to as part of its
 * incorporation into secnet.
 *
 * Copyright 2000 Vincent Rijmen, Antoon Bosselaers, Paulo Barreto
 * Copyright 2004 Fabrice Bellard
 * Copyright 2013 Ian Jackson
 *
 * You may redistribute this file and/or modify it under the terms of
 * the permissive licence shown below.
 *
 * You may redistribute secnet as a whole and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * https://www.gnu.org/licenses/gpl.html.
 */
/*
  * Copied from the upstream qemu git tree revision
  *   55616505876d6683130076b810a27c7889321560
  * but was introduced there by Fabrice Bellard in
  *   e4d4fe3c34cdd6e26f9b9975efec7d1e81ad00b6
  *   AES crypto support
  *   git-svn-id: svn://svn.savannah.nongnu.org/qemu/trunk@1036 \
  *     c046a42c-6fe2-441c-8c8c-71466251a162
  *
  * Modified by Ian Jackson to change the guard #define from
  * QEMU_AES_H to AES_H and to add some needed system #include's.
  *
  * The header file doesn't appear to have a separate copyright notice
  * but is clearly a lightly edited (by Bellard) version of code from
  * Rijmen, Bosselaers and Barreto.
  *
  * The original is from rijndael-alg-fst.c, with this copyright
  * notice:
  *
  *   rijndael-alg-fst.c
  *   
  *   @version 3.0 (December 2000)
  *   
  *   Optimised ANSI C code for the Rijndael cipher (now AES)
  *   
  *   @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
  *   @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
  *   @author Paulo Barreto <paulo.barreto@terra.com.br>
  *   
  *   This code is hereby placed in the public domain.
  *   
  *   THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
  *   OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  *   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  *   ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
  *   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  *   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  *   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
  *   BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  *   WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
  *   OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
  *   EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *
  */

#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <assert.h>
#include <string.h>

#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16

struct aes_key_st {
    uint32_t rd_key[4 *(AES_MAXNR + 1)];
    int rounds;
};
typedef struct aes_key_st AES_KEY;

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
	AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
	AES_KEY *key);

void AES_encrypt(const unsigned char *in, unsigned char *out,
	const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out,
	const AES_KEY *key);
void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
		     const unsigned long length, const AES_KEY *key,
		     unsigned char *ivec, const int enc);

#endif /* AES_H */
