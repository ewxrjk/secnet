/* $Log: util.h,v $
 * Revision 1.1  1996/03/14 17:05:12  sde1000
 * Initial revision
 *
 */

#ifndef util_h
#define util_h

#include "secnet.h"
#include <gmp.h>

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

extern void buffer_assert_free(struct buffer_if *buffer, string_t file,
			       uint32_t line);
extern void buffer_assert_used(struct buffer_if *buffer, string_t file,
			       uint32_t line);
extern void buffer_new(struct buffer_if *buffer, uint32_t len);
extern void buffer_init(struct buffer_if *buffer, uint32_t max_start_pad);
extern void *buf_append(struct buffer_if *buf, uint32_t amount);
extern void *buf_prepend(struct buffer_if *buf, uint32_t amount);
extern void *buf_unappend(struct buffer_if *buf, uint32_t amount);
extern void *buf_unprepend(struct buffer_if *buf, uint32_t amount);

extern void buf_append_string(struct buffer_if *buf, string_t s);

extern void read_mpbin(MP_INT *a, uint8_t *bin, int binsize);

extern char *write_mpstring(MP_INT *a);

extern uint32_t write_mpbin(MP_INT *a, uint8_t *buffer, uint32_t buflen);

extern struct log_if *init_log(list_t *loglist);

#endif /* util_h */
