/*
 * basE91 length calculation test
 *
 * Copyright (c) 2019 Ian Jackson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of Joachim Henke nor the names of his contributors may
 *    be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "base91.h"

static size_t upto = (14*16 + 14 + 16)*2;

static int do_test(int do_do, int fill, const char *what,
	size_t f(struct basE91 *, const void *, size_t, void *),
	size_t f_end(struct basE91 *, void *),
	size_t f_maxlen(size_t)
										)
{
	struct basE91 b;
	size_t i, o, exp;
	int bad = 0;
	char ibuf[upto];
	char obuf[upto*2+100]; /* in case we have bugs */

	memset(ibuf,fill,upto);

	if (!do_do) {
		printf("%s: skipping\n",what);
		return 0;
	}

	for (i=0; i<upto; i++) {
		basE91_init(&b);
		o = f(&b, ibuf, i, obuf);
		o += f_end(&b, obuf+o);

		exp = f_maxlen(i);
		if (o == exp) continue;

		bad = 1;
		fprintf(stderr,"%s: i=%lu o=%lu expected=%lu\n",
						what, (unsigned long)i, (unsigned long)o, (unsigned long)exp);
	}
	return bad;
}

int main(int argc, const char **argv) {
	int do_encode=1, do_decode=1, bad=0;

	if (argc>=2) {
		do_encode = !!strchr(argv[1],'e');
		do_decode = !!strchr(argv[1],'d');
	}
	if (argc>=3) {
		upto = atoi(argv[2]);
	}

#define MAYBE_DO_TEST(ed, fill) \
	(bad |= do_test(do_##ed, (fill), #ed, \
									basE91_##ed, basE91_##ed##_end, basE91_##ed##_maxlen))
	MAYBE_DO_TEST(encode, 0xff);
	MAYBE_DO_TEST(decode, 'A');

	if (bad) exit(8);
	printf("ok\n");
	exit(0);
}
