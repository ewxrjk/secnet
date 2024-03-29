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

#ifndef unaligned_h
#define unaligned_h

#include <stdint.h>
#include "util.h"

/* Parts of the secnet key-exchange protocol require access to
   unaligned big-endian quantities in buffers. These macros provide
   convenient access, even on architectures that don't support unaligned
   accesses. */

#define put_uint32(a,v) do { (a)[0]=(v)>>24; (a)[1]=((v)&0xff0000)>>16; \
(a)[2]=((v)&0xff00)>>8; (a)[3]=(v)&0xff; } while(0)

#define put_uint16(a,v) do {(a)[0]=((v)&0xff00)>>8; (a)[1]=(v)&0xff;} while(0)

#define put_uint8(a,v) do {(a)[0]=((v)&0xff);} while(0)

#define get_uint32(a)					\
  (((uint32_t)(a)[0]<<24) | ((uint32_t)(a)[1]<<16) |	\
   ((uint32_t)(a)[2]<<8)  |  (uint32_t)(a)[3])

#define get_uint16(a) (((uint16_t)(a)[0]<<8)|(uint16_t)(a)[1])

#define get_uint8(a) (((uint8_t)(a)[0]))

#define UNALIGNED_DEF_FORTYPE(type,appre)				\
static inline void buf_##appre##_##type(struct buffer_if *buf, type##_t v) \
{									\
    uint8_t *c=buf_##appre(buf,sizeof(type##_t));			\
    put_##type(c,v);							\
}									\
static inline type##_t buf_un##appre##_##type(struct buffer_if *buf)	\
{									\
    const uint8_t *c=buf_un##appre(buf,sizeof(type##_t));		\
    return get_##type(c);						\
}

UNALIGNED_DEF_FORTYPE(uint32,append)
UNALIGNED_DEF_FORTYPE(uint16,append)
UNALIGNED_DEF_FORTYPE(uint8,append)
UNALIGNED_DEF_FORTYPE(uint32,prepend)
UNALIGNED_DEF_FORTYPE(uint16,prepend)
UNALIGNED_DEF_FORTYPE(uint8,prepend)

#endif /* unaligned_h */
