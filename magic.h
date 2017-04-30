/* Magic numbers used within secnet */
/*
 * This file is part of secnet.
 * See README for full list of copyright holders.
 *
 * secnet is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#ifndef magic_h
#define magic_h

/* Encode a pair of 16 bit major and minor codes as a single 32-bit label.
 * The encoding is strange for historical reasons.  Suppose that the nibbles
 * of the major number are (from high to low) a, b, c, d, and the minor
 * number has nibbles w, x, y, z.  (Here, a, b, c, d are variables, not hex
 * digits.)  We scramble them to form a message label as follows.
 *
 *	0 d 0 d 0 d 0 d
 *	0 0 0 a b c 0 0
 *	z 0 0 0 0 0 z 0
 *	w x y 0 0 0 0 0
 *	---------------
 *	f g h i j k l m
 *
 * and calculate the nibbles f, g, ..., m of the message label (higher
 * significance on the left) by XORing the columns.  It can be shown that
 * this is invertible using linear algebra in GF(16), but but it's easier to
 * notice that d = m, z = l, c = k XOR d, b = j, a = i XOR d, y = h,
 * x = g XOR d, and w = f XOR z.
 *
 * Encoding in the forward direction, from a major/minor pair to a label, is
 * (almost?) always done on constants, so its performance is fairly
 * unimportant.  There is a compatibility constraint on the patterns produced
 * with a = b = c = w = x = y = 0.  Subject to that, I wanted to find an
 * invertible GF(16)-linear transformation which would let me recover the
 * major and minor numbers with relatively little calculation.
 */

#define MSGCODE(major, minor)						\
	((((uint32_t)(major)&0x0000000fu) <<  0) ^			\
	 (((uint32_t)(major)&0x0000000fu) <<  8) ^			\
	 (((uint32_t)(major)&0x0000000fu) << 16) ^			\
	 (((uint32_t)(major)&0x0000000fu) << 24) ^			\
	 (((uint32_t)(major)&0x0000fff0u) <<  4) ^			\
	 (((uint32_t)(minor)&0x0000000fu) <<  4) ^			\
	 (((uint32_t)(minor)&0x0000000fu) << 28) ^			\
	 (((uint32_t)(minor)&0x0000fff0u) << 16))

/* Extract major and minor codes from a 32-bit message label. */
#define MSGMAJOR(label)							\
	((((uint32_t)(label)&0x0000000fu) <<  0) ^			\
	 (((uint32_t)(label)&0x0000000fu) <<  4) ^			\
	 (((uint32_t)(label)&0x0000000fu) << 12) ^			\
	 (((uint32_t)(label)&0x000fff00u) >>  4))
#define MSGMINOR(label)							\
	((((uint32_t)(label)&0x000000ffu) <<  8) ^			\
	 (((uint32_t)(label)&0x000000f0u) >>  4) ^			\
	 (((uint32_t)(label)&0xfff00000u) >> 16))

#define LABEL_NAK	MSGCODE(     0, 0)
#define LABEL_MSG0	MSGCODE(0x2020, 0) /* ! */
#define LABEL_MSG1	MSGCODE(     1, 0)
#define LABEL_MSG2	MSGCODE(     2, 0)
#define LABEL_MSG3	MSGCODE(     3, 0)
#define LABEL_MSG3BIS	MSGCODE(     3, 1)
#define LABEL_MSG4	MSGCODE(     4, 0)
#define LABEL_MSG5	MSGCODE(     5, 0)
#define LABEL_MSG6	MSGCODE(     6, 0)
#define LABEL_MSG7	MSGCODE(     7, 0)
#define LABEL_MSG8	MSGCODE(     8, 0)
#define LABEL_MSG9	MSGCODE(     9, 0)
#define LABEL_PROD	MSGCODE(    10, 0)

/*
 * The capability mask is a set of bits, one for each optional feature
 * supported.  The capability numbers for transforms are set in the
 * configuration (and should correspond between the two sites), although
 * there are sensible defaults.
 *
 * Advertising a nonzero capability mask promises that the receiver
 * understands LABEL_MSG3BIS messages, which contain an additional byte
 * specifying the transform capability number actually chosen by the MSG3
 * sender.
 *
 * Aside from that, an empty bitmask is treated the same as
 *  1u<<CAPAB_BIT_ANCIENTTRANSFORM
 */

/* uses of the 32-bit capability bitmap */
#define CAPAB_TRANSFORM_MASK  0x0000ffff
#define CAPAB_PRIORITY_MOBILE 0x80000000 /* mobile site has MSG1 priority */
/* remaining bits are unused */

/* bit indices, 0 is ls bit */
#define CAPAB_BIT_USER_MIN              0
#define CAPAB_BIT_USER_MAX              7
#define CAPAB_BIT_SERPENT256CBC         8
#define CAPAB_BIT_EAXSERPENT            9
#define CAPAB_BIT_MAX                  15

#define CAPAB_BIT_ANCIENTTRANSFORM CAPAB_BIT_SERPENT256CBC

#endif /* magic_h */
