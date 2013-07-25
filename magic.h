/* Magic numbers used within secnet */

#ifndef magic_h
#define magic_h

#define LABEL_NAK  0x00000000
#define LABEL_MSG0 0x00020200
#define LABEL_MSG1 0x01010101
#define LABEL_MSG2 0x02020202
#define LABEL_MSG3 0x03030303
#define LABEL_MSG4 0x04040404
#define LABEL_MSG5 0x05050505
#define LABEL_MSG6 0x06060606
#define LABEL_MSG7 0x07070707
#define LABEL_MSG8 0x08080808
#define LABEL_MSG9 0x09090909

/* uses of the 32-bit capability bitmap */
/* no flags currently defined */
#define CAPAB_EARLY 0x00000000 /* no Early flags defined (see NOTES) */

#endif /* magic_h */
