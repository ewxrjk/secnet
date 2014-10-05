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

extern void read_mpbin(MP_INT *a, uint8_t *bin, int binsize);

extern char *write_mpstring(MP_INT *a);

extern int32_t write_mpbin(MP_INT *a, uint8_t *buffer, int32_t buflen);

extern struct log_if *init_log(list_t *loglist);

extern void send_nak(const struct comm_addr *dest, uint32_t our_index,
		     uint32_t their_index, uint32_t msgtype,
		     struct buffer_if *buf, const char *logwhy);

extern int consttime_memeq(const void *s1, const void *s2, size_t n);

const char *iaddr_to_string(const union iaddr *ia);
int iaddr_socklen(const union iaddr *ia);

#define MINMAX(ae,be,op) ({			\
	typeof((ae)) a=(ae);			\
	typeof((be)) b=(be);			\
	a op b ? a : b;				\
    })
#define MAX(a,b) MINMAX((a),(b),>)
#define MIN(a,b) MINMAX((a),(b),<)

#endif /* util_h */
