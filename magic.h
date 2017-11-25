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

#define LABEL_NAK     0x00000000
#define LABEL_MSG0    0x00020200
#define LABEL_MSG1    0x01010101
#define LABEL_MSG2    0x02020202
#define LABEL_MSG3    0x03030303
#define LABEL_MSG3BIS 0x13030313
#define LABEL_MSG4    0x04040404
#define LABEL_MSG5    0x05050505
#define LABEL_MSG6    0x06060606
#define LABEL_MSG7    0x07070707
#define LABEL_MSG8    0x08080808
#define LABEL_MSG9    0x09090909
#define LABEL_PROD    0x0a0a0a0a

/* uses of the 32-bit capability bitmap */
#define CAPAB_EARLY           0x00000000 /* no Early flags yet (see NOTES) */
#define CAPAB_TRANSFORM_MASK  0x0000ffff
/* remaining 16 bits are unused */

/*
 * The transform capability mask is a set of bits, one for each
 * transform supported.  The transform capability numbers are set in
 * the configuration (and should correspond between the two sites),
 * although there are sensible defaults.
 *
 * Advertising a nonzero transform capability mask promises that
 * the receiver understands LABEL_MSG3BIS messages, which
 * contain an additional byte specifying the transform capability
 * number actually chosen by the MSG3 sender.
 *
 * Aside from that, an empty bitmask is treated the same as
 *  1u<<CAPAB_TRANSFORMNUM_ANCIENT
 */

/* bit indices, 0 is ls bit */
#define CAPAB_TRANSFORMNUM_USER_MIN              0
#define CAPAB_TRANSFORMNUM_USER_MAX              7
#define CAPAB_TRANSFORMNUM_SERPENT256CBC         8
#define CAPAB_TRANSFORMNUM_EAXSERPENT            9
#define CAPAB_TRANSFORMNUM_MAX                  15

#define CAPAB_TRANSFORMNUM_ANCIENT CAPAB_TRANSFORMNUM_SERPENT256CBC

#endif /* magic_h */
