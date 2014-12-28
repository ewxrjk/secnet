/*
 * eax-test.c: test harness for EAX, implementation
 */
/*
 * This file is Free Software.  It was originally written for secnet.
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

/*
 * usages:
 *   ./eax-foo-test <eax-foo-test.vectors
 *      runs the test vectors, regenerates the file on stdout
 *   grep -v CIPHER <eax-foo-test.vectors | ./eax-foo-test
 *      generates output with CIPHER lines reinserted
 * All errors result in calls to abort().
 */

#include "eax-test.h"

struct valbuf {
    _Bool got;
    uint8_t v[1024];
    size_t len;
};
#define V(vb) ((vb).v), ((vb).len)

static struct valbuf msg, key, nonce, header, cipher, ourcipher, returnplain;
static size_t tau;

static void trydecrypt(_Bool expected)
{
    _Bool actual = eax_decrypt(-1, V(nonce), V(header), V(ourcipher), tau,
			       returnplain.v);
    assert(actual == expected);
    if (actual) {
	returnplain.len = ourcipher.len - tau;
	assert(returnplain.len == msg.len);
	assert(!memcmp(returnplain.v, msg.v, msg.len));
    }
}

static void negtest(struct valbuf *perturb)
{
    unsigned delta = 0x04;
    size_t i;
    for (i=0; i<perturb->len; i++) {
	perturb->v[i] ^= delta;
	trydecrypt(0);
	perturb->v[i] ^= delta;
    }
}

static void something(void)
{
    if (!msg.got) return;
    assert(key.got);
    assert(nonce.got);
    assert(header.got);
    eaxtest_blockcipher_key_setup(V(key));
    eax_setup(-1);
    if (cipher.got) {
	assert(cipher.len > msg.len);
	tau = cipher.len - msg.len;
	assert(tau <= blocksize);
    } else {
	assert(msg.len + blocksize < sizeof(ourcipher.v));
	tau = blocksize;
    }
    ourcipher.len = msg.len + tau;
    eax_encrypt(-1, V(nonce), V(header), V(msg), tau, ourcipher.v);
    if (cipher.got) {
	assert(ourcipher.len == cipher.len);
	assert(!memcmp(ourcipher.v, cipher.v, cipher.len));
	trydecrypt(1);
	negtest(&ourcipher);
	negtest(&header);
    } else {
	size_t i;
	printf("CIPHER: ");
	for (i=0; i<ourcipher.len; i++)
	    printf("%02X", ourcipher.v[i]);
	putchar('\n');
    }
    msg.got=key.got=nonce.got=header.got=0;
}

static int getputchar(void)
{
    int c = getchar();
    assert(c != EOF);
    putchar(c);
    return c;
}

int main(int argc, const char *const *argv)
{
    struct valbuf *cv;

    assert(argc==1);

    for (;;) {
	int c = getchar();
	switch (c) {
	case 'M':  something();  cv = &msg;     putchar(c);  break;
	case 'K':                cv = &key;     putchar(c);  break;
	case 'N':                cv = &nonce;   putchar(c);  break;
	case 'H':                cv = &header;  putchar(c);  break;
	case 'C':                cv = &cipher;  putchar(c);  break;
	case '\n':                              putchar(c);  continue;
	case EOF:  something();  exit(0);
	default:   assert(!"unexpected input");
	}
	cv->got = 1;
	cv->len = 0;
	for (;;) {
	    c = getputchar();
	    if (c == ':') break;
	    assert(isalpha(c));
	}
	for (;;) {
	    char hbuf[3], *ep;
	    c = getputchar();
	    if (c == '\n') break;
	    if (isspace(c)) continue;
	    assert(isprint(c));
	    hbuf[0] = c;
	    c = getputchar();
	    assert(isprint(c));
	    hbuf[1] = c;
	    hbuf[2] = 0;
	    assert(cv->len < sizeof(cv->v));
	    cv->v[cv->len++] = strtoul(hbuf,&ep,16);
	    assert(!*ep);
	}
    }
    assert(!ferror(stdin));
    assert(feof(stdin));
    assert(!ferror(stdout));
    assert(!fflush(stdout));
    return 0;
}
