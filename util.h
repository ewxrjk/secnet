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

#define MINMAX(ae,be,op) ({			\
	typeof((ae)) a=(ae);			\
	typeof((be)) b=(be);			\
	a op b ? a : b;				\
    })
#define MAX(a,b) MINMAX((a),(b),>)
#define MIN(a,b) MINMAX((a),(b),<)

#endif /* util_h */
