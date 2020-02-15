#!/usr/bin/awk -f

# basE91 decoder
# Copyright (c) 2000-2006 Joachim Henke
# http://base91.sourceforge.net/

BEGIN {
	b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
	for (i = 0; i < 256; ++i) {
		--d[sprintf("%c", i)]
	}
	for (i = 0; i < 91; ++i) {
		d[substr(b, i + 1, 1)] = i
	}
	b = 0
	n = 0
	v = -1
}

{
	l = length($0)
	for (i = 1; i <= l; ++i) {
		c = d[substr($0, i, 1)]
		if (c < 0) {
			continue
		}
		if (v < 0) {
			v = c
		} else {
			v += c * 91
			b += v * 2 ^ n
			n += v % 8192 > 88 ? 13 : 14
			do {
				b -= c = b % 256
				printf "%c", c
				b /= 256
				n -= 8
			} while (n > 7)
			v = -1
		}
	}
}

END {
	if (v + 1) {
		printf "%c", b + v * 2 ^ n
	}
}
