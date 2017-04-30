/*
 * msgcode-test.c: check that the new message encoding is correct
 */
/*
 * This file is Free Software.  It was originally written for secnet.
 *
 * Copyright 2017 Mark Wooding
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

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "magic.h"

#define OLD_LABEL_NAK     0x00000000
#define OLD_LABEL_MSG0    0x00020200
#define OLD_LABEL_MSG1    0x01010101
#define OLD_LABEL_MSG2    0x02020202
#define OLD_LABEL_MSG3    0x03030303
#define OLD_LABEL_MSG3BIS 0x13030313
#define OLD_LABEL_MSG4    0x04040404
#define OLD_LABEL_MSG5    0x05050505
#define OLD_LABEL_MSG6    0x06060606
#define OLD_LABEL_MSG7    0x07070707
#define OLD_LABEL_MSG8    0x08080808
#define OLD_LABEL_MSG9    0x09090909
#define OLD_LABEL_PROD    0x0a0a0a0a

static void check_labels(const char *what, uint32_t new, uint32_t old)
{
    if (old != new) {
	printf("mismatch for %s: %08"PRIx32" (new) /= %08"PRIx32" (old)\n",
	       what, new, old);
	exit(2);
    }
}

int main(void)
{
    unsigned i, j;
    uint32_t m, r, s;

#define CHECK(label) check_labels(#label, LABEL_##label, OLD_LABEL_##label)
    CHECK(NAK);
    CHECK(MSG0);
    CHECK(MSG1);
    CHECK(MSG2);
    CHECK(MSG3);
    CHECK(MSG3BIS);
    CHECK(MSG4);
    CHECK(MSG5);
    CHECK(MSG6);
    CHECK(MSG7);
    CHECK(MSG8);
    CHECK(MSG9);
    CHECK(PROD);
#undef CHECK
    for (i = 0; i < 65536; i++) {
	for (j = 0; j < 65536; j++) {
	    m = MSGCODE(i, j);
	    r = MSGMAJOR(m); s = MSGMINOR(m);
	    if (r != i || s != j) {
		printf("roundtrip fail: %04x %04x -> %08"PRIx32" "
		       "-> %08"PRIx32" %08"PRIx32"\n",
		       i, j, m, r, s);
		exit(2);
	    }
	}
    }

    return (0);
}
