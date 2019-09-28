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

#ifndef util_h
#define util_h

#include "secnet.h"
#include <gmp.h>

#include "hackypar.h"

#define BUF_ASSERT_FREE(buf) do { buffer_assert_free((buf), \
						     __FILE__,__LINE__); } \
while(0)
#define BUF_ASSERT_USED(buf) do { buffer_assert_used((buf), \
						     __FILE__,__LINE__); } \
while(0)
#define BUF_ALLOC(buf,own) do { buffer_assert_free((buf),__FILE__,__LINE__); \
	 (buf)->free=False; (buf)->owner=(own); (buf)->start=(buf)->base; \
	 (buf)->size=0; } while(0)
#define BUF_FREE(buf) do { (buf)->free=True; } while(0)

extern void buffer_assert_free(struct buffer_if *buffer, cstring_t file,
			       int line);
extern void buffer_assert_used(struct buffer_if *buffer, cstring_t file,
			       int line);
extern void buffer_new(struct buffer_if *buffer, int32_t len);
extern void buffer_init(struct buffer_if *buffer, int32_t max_start_pad);
extern void buffer_destroy(struct buffer_if *buffer);
extern void buffer_copy(struct buffer_if *dst, const struct buffer_if *src);
extern void *buf_append(struct buffer_if *buf, int32_t amount);
extern void *buf_prepend(struct buffer_if *buf, int32_t amount);
extern void *buf_unappend(struct buffer_if *buf, int32_t amount);
extern void *buf_unprepend(struct buffer_if *buf, int32_t amount);

/*
 * void BUF_ADD_BYTES(append,    struct buffer_if*, const void*, int32_t size);
 * void BUF_ADD_BYTES(prepend,   struct buffer_if*, const void*, int32_t size);
 * void BUF_GET_BYTES(unappend,  struct buffer_if*,       void*, int32_t size);
 * void BUF_GET_BYTES(unprepend, struct buffer_if*,       void*, int32_t size);
 *     // all of these evaluate size twice
 *
 * void BUF_ADD_OBJ(append,    struct_buffer_if*, const OBJECT& something);
 * void BUF_ADD_OBJ(prepend,   struct_buffer_if*, const OBJECT& something);
 * void BUF_GET_OBJ(unappend,  struct_buffer_if*,       OBJECT& something);
 * void BUF_GET_OBJ(unprepend, struct_buffer_if*,       OBJECT& something);
 */
#define BUF_ADD_BYTES(appendprepend, bufp, datap, size)			\
    (buf_un##appendprepend /* ensures we have correct direction */,	\
     memcpy(buf_##appendprepend((bufp),(size)),(datap),(size)))
#define BUF_ADD_OBJ(appendprepend, bufp, obj) \
    BUF_ADD_BYTES(appendprepend,(bufp),&(obj),sizeof((obj)))
#define BUF_GET_BYTES(unappendunprepend, bufp, datap, size)		\
    (BUF_GET__DOESNOTEXIST__buf_un##unappendunprepend,			\
     memcpy((datap),buf_##unappendunprepend((bufp),(size)),(size)))
#define BUF_GET_OBJ(unappendunprepend, bufp, obj) \
    BUF_ADD_BYTES(unappendunprepend,&(obj),(bufp),sizeof((obj)))
#define BUF_GET__DOESNOTEXIST__buf_ununappend  0
#define BUF_GET__DOESNOTEXIST__buf_ununprepend 0

static inline int32_t buf_remaining_space(const struct buffer_if *buf)
{
    return (buf->base + buf->alloclen) - (buf->start + buf->size);
}

extern void buffer_readonly_view(struct buffer_if *n, const void*, int32_t len);
extern void buffer_readonly_clone(struct buffer_if *n, const struct buffer_if*);
  /* Caller must only use unappend, unprepend et al. on n.
   * New buffer state (in n) before this can be undefined.  After use,
   * it must NOT be freed. */

extern void buf_append_string(struct buffer_if *buf, cstring_t s);
  /* Append a two-byte length and the string to the buffer. Length is in
   * network byte order. */

extern string_t hex_encode(const uint8_t *bin, int binsize);
  /* Convert a byte array to hex, returning the result in a freshly allocated
   * string. */

extern bool_t hex_decode(uint8_t *buffer, int32_t buflen, int32_t *outlen,
			 cstring_t hb, bool_t allow_odd_nibble);
  /* Convert a hex string to binary, storing the result in buffer.  If
   * allow_odd_nibble then it is acceptable if the input is an odd number of
   * digits, and an additional leading zero digit is assumed; otherwise, this
   * is not acceptable and the conversion fails.
   *
   * The input is processed left to right until it is consumed, the buffer is
   * full, or an error is encountered in the input.  The length of output
   * produced is stored in *outlen.  Returns true if the entire input was
   * processed without error; otherwise false. */

extern void read_mpbin(MP_INT *a, uint8_t *bin, int binsize);
  /* Convert a buffer into its MP_INT representation */

extern char *write_mpstring(MP_INT *a);
  /* Convert a MP_INT into a hex string */

extern int32_t write_mpbin(MP_INT *a, uint8_t *buffer, int32_t buflen);
  /* Convert a MP_INT into a buffer; return length; truncate if necessary */

extern struct log_if *init_log(list_t *loglist);

extern void send_nak(const struct comm_addr *dest, uint32_t our_index,
		     uint32_t their_index, uint32_t msgtype,
		     struct buffer_if *buf, const char *logwhy);

extern int consttime_memeq(const void *s1, const void *s2, size_t n);

const char *iaddr_to_string(const union iaddr *ia);
int iaddr_socklen(const union iaddr *ia);

void string_item_to_iaddr(const item_t *item, uint16_t port, union iaddr *ia,
			  const char *desc);


/*
 * SBUF_DEFINE(int nbufs, size_t size);
 *   // Generates a number of definitions and statements organising
 *   // nbufs rotating char[size] buffers such that subsequent code
 *   // may refer to:
 * char *const SBUF;
 */
#define SBUF_DEFINE(nbufs, size)			\
    static int static_bufs__bufnum;			\
    static char static_bufs__bufs[(nbufs)][(size)];	\
    static_bufs__bufnum++;				\
    static_bufs__bufnum %= (nbufs);			\
    static_bufs__bufs[static_bufs__bufnum]
#define SBUF (static_bufs__bufs[static_bufs__bufnum])

/*----- line-buffered asynch input -----*/

enum async_linebuf_result {
    async_linebuf_nothing,
    async_linebuf_ok,
    async_linebuf_eof,
    async_linebuf_broken,
};

const char *pollbadbit(int revents); /* returns 0, or bad bit description */

enum async_linebuf_result
async_linebuf_read(struct pollfd *pfd, struct buffer_if *buf,
		   const char **emsg_out);
   /* Implements reading whole lines, asynchronously.  Use like
    * this:
    *   - set up the fd, which should be readable, O_NONBLOCK
    *   - set up and initialise buffer, which should be big enough
    *     for one line plus its trailing newline, and be empty
    *     with start==base
    *   - in your beforepoll_fn, be interested in POLLIN
    *   - in your afterpoll_fn, repeatedly call this function
    *     until it doesn't return `nothing'
    *   - after you're done, simply close fd and free or reset buf
    * State on return from async_linebuf_read depends on return value:
    *
    *   async_linebuf_nothing:
    *
    *      No complete lines available right now.  You should return
    *      from afterpoll.  buf should be left untouched until the
    *      next call to async_linebuf_read.
    *
    *   async_linebuf_ok:
    *
    *      buf->base contains a input line as a nul-terminated string
    *      (\n replaced by \0); *emsg_out==0.  You must call
    *      async_linebuf_read again before returning from afterpoll.
    *
    *   async_linebuf_eof:
    *
    *      EOF on stream.  buf->base contains any partial
    *      (non-newline-terminated) line; *emsg_out!=0 iff there was
    *      such a partial line.  You can call async_linebuf_read again
    *      if you like but it will probably just return eof again.
    *
    *   broken:
    *
    *      Fatal problem (might be overly long lines, nuls in input
    *      data, bad bits in pfd->revents, errors from read, etc.)
    *
    *      *emsg_out is the error message describing the problem;
    *      this message might be stored in buf, might be from
    *      strerror, or might be a constant.
    *
    *      You must not call async_linebuf_read again.  buf contents
    *      is undefined: it is only safe to reset or free.
    *
    * While using this function, do not look at buf->start or ->size
    * or anything after the first '\0' in buf.
    *
    * If you decide to stop reading with async_linebuf_read that's
    * fine and you can reset or free buf, but you risk missing some
    * read-but-not-reported data.
    */

/*----- some handy macros -----*/

#define MINMAX(ae,be,op) ({			\
	typeof((ae)) a=(ae);			\
	typeof((be)) b=(be);			\
	a op b ? a : b;				\
    })
#define MAX(a,b) MINMAX((a),(b),>)
#define MIN(a,b) MINMAX((a),(b),<)

#define MAX_RAW(a,b) ((a)>(b)?(a):(b))
#define MIN_RAW(a,b) ((a)<(b)?(a):(b))

static inline bool_t iswouldblock(int e)
    { return e==EWOULDBLOCK || e==EAGAIN; }

#endif /* util_h */
