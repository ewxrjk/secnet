#ifndef unaligned_h
#define unaligned_h

/* Parts of the secnet key-exchange protocol require access to
   unaligned big-endian quantities in buffers. These macros provide
   convenient access, even on architectures that don't support unaligned
   accesses. */

#define put_uint32(a,v) do { (a)[0]=(v)>>24; (a)[1]=((v)&0xff0000)>>16; \
(a)[2]=((v)&0xff00)>>8; (a)[3]=(v)&0xff; } while(0)

#define put_uint16(a,v) do {(a)[0]=((v)&0xff00)>>8; (a)[1]=(v)&0xff;} while(0)

#define get_uint32(a) (((a)[0]<<24)|((a)[1]<<16)|((a)[2])<<8|(a)[3])

#define get_uint16(a) (((a)[0]<<8)|(a)[1])

#define buf_append_uint32(buf,v) do { uint8_t *c=buf_append((buf),4); \
    put_uint32(c,(v)); } while(0)

#define buf_append_uint16(buf,v) do { uint8_t *c=buf_append((buf),2); \
	put_uint16(c,(v)); } while(0)

#define buf_prepend_uint32(buf,v) do { uint8_t *c=buf_prepend((buf),4); \
	    put_uint32(c,(v)); } while(0)

#define buf_prepend_uint16(buf,v) do { uint8_t *c=buf_prepend((buf),2); \
		put_uint16(c,(v)); } while(0)

#define buf_unappend_uint32(buf) ({uint8_t *c=buf_unappend((buf),4); \
		    get_uint32(c);})

#define buf_unappend_uint16(buf) ({uint8_t *c=buf_unappend((buf),2); \
			get_uint16(c);})

#define buf_unprepend_uint32(buf) ({uint8_t *c=buf_unprepend((buf),4); \
			get_uint32(c);})

#define buf_unprepend_uint16(buf) ({uint8_t *c=buf_unprepend((buf),2); \
			get_uint16(c);})

#endif /* unaligned_h */
