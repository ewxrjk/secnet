/*
 * eax-transform.c: EAX-Serpent bulk data transformation
 *
 * We use EAX with the following parameters:
 *
 *   Plaintext:
 *      Concatenation of:
 *        Data packet as supplied to us
 *        Zero or more zero bytes ignored by receiver } padding
 *        One byte padding length                     }
 *      This is a bit like PKCS#5.  It helps disguise message lengths.
 *      It also provides a further room for future expansion.  When
 *      transmitting we pad the message to the next multiple of
 *      a configurable rounding factor, 16 bytes by default.
 *
 *   Transmitted message:
 *      Concatenation of:
 *        EAX ciphertext
 *        32-bit sequence number (initially zero)
 *      The sequence number allows us to discard far-too-old
 *      packets.
 *
 *   Nonce:
 *      Concatenation of:
 *        32-bit sequence number (big endian)
 *               initial value comes from SHA-512 hash (see below)
 *        1 byte: 0x01 if sender has setup priority, 0x00 if it doesn't
 *               (ie, the direction of data flow)
 *
 *   Header: None
 *
 *   Tag length:
 *      16 bytes (128 bits) by default
 *
 *   Key:
 *      The first 32 bytes of the SHA-512 hash of the shared secret
 *      from the DH key exchange (the latter being expressed as
 *      the shortest possible big-endian octet string).
 *
 * The bytes [32,40> of the hash of the shared secret are used for
 * initial sequence numbers: [32,36> for those sent by the end without
 * setup priority, [36,40> for those for the other end.
 *
 */

#include "secnet.h"
#include "unaligned.h"
#include "util.h"
#include "serpent.h"
#include "sha512.h"
#include "transform-common.h"
#include "hexdebug.h"

#define BLOCK_SIZE 16
#define SEQLEN 4

struct transform_params {
    uint32_t max_seq_skew, tag_length, padding_mask;
};

struct transform {
    closure_t cl;
    struct transform_if ops;
    struct transform_params p;
};

struct transform_inst {
    struct transform_inst_if ops;
    struct transform_params p;
    unsigned keyed:1;
    /* remaining valid iff keyed */
    unsigned direction:1;
    uint32_t sendseq;
    uint32_t lastrecvseq;
    struct keyInstance key;
    uint8_t info_b[BLOCK_SIZE], info_p[BLOCK_SIZE];
};

static void block_encrypt(struct transform_inst *transform_inst,
			  uint8_t dst[BLOCK_SIZE],
			  const uint8_t src[BLOCK_SIZE])
{
    serpent_encrypt(&transform_inst->key, src, dst);
}

#define INFO                    struct transform_inst *transform_inst
#define I                       transform_inst
#define EAX_ENTRYPOINT_DECL     static
#define BLOCK_ENCRYPT(dst,src)  block_encrypt(transform_inst,dst,src)
#define INFO_B                  (transform_inst->info_b)
#define INFO_P                  (transform_inst->info_p)

#include "eax.c"

#if 0

#define TEAX_DEBUG(ary,sz) teax_debug(__func__,__LINE__,#ary,#sz,ary,sz)
static void teax_debug(const char *func, int line,
		       const char *aryp, const char *szp,
		       const void *ary, size_t sz)
{
    fprintf(stderr,"TEAX %s:%-3d %10s %15s : ", func,line,aryp,szp);
    hexdebug(stderr,ary,sz);
    fprintf(stderr,"\n");
}

#else

#define TEAX_DEBUG(ary,sz) /* empty */

#endif

static bool_t transform_setkey(void *sst, uint8_t *key, int32_t keylen,
			       bool_t direction)
{
    struct transform_inst *ti=sst;
    struct sha512_ctx hash_ctx;
    uint8_t hash_out[64];

    TEAX_DEBUG(key,keylen);

    sha512_init_ctx(&hash_ctx);
    sha512_process_bytes(key, keylen, &hash_ctx);
    sha512_finish_ctx(&hash_ctx, hash_out);

    TEAX_DEBUG(hash_out,32);
    TEAX_DEBUG(hash_out+32,8);

    ti->direction=direction;
    ti->sendseq=get_uint32(hash_out+32+direction*4);
    ti->lastrecvseq=get_uint32(hash_out+32+!direction*4);
    serpent_makekey(&ti->key, 32*8, hash_out);
    eax_setup(ti);
    ti->keyed=True;

    return True;
}

TRANSFORM_VALID;

TRANSFORM_DESTROY;

static void transform_delkey(void *sst)
{
    struct transform_inst *ti=sst;

    FILLZERO(ti->key);
    FILLZERO(ti->info_b);
    FILLZERO(ti->info_p);
    ti->keyed=False;
}

static uint32_t transform_forward(void *sst, struct buffer_if *buf,
				  const char **errmsg)
{
    struct transform_inst *ti=sst;

    KEYED_CHECK;
    
    size_t padlen = ti->p.padding_mask - buf->size;
    padlen &= ti->p.padding_mask;
    padlen++;

    uint8_t *pad = buf_append(buf,padlen);
    memset(pad, 0, padlen-1);
    pad[padlen-1] = padlen;

    uint8_t nonce[SEQLEN+1];
    put_uint32(nonce,ti->sendseq);
    nonce[SEQLEN] = ti->direction;

    TEAX_DEBUG(nonce,sizeof(nonce));
    TEAX_DEBUG(buf->start,buf->size);

    assert(buf_append(buf,ti->p.tag_length));
    eax_encrypt(ti, nonce,sizeof(nonce), 0,0,
		buf->start,buf->size-ti->p.tag_length,
		ti->p.tag_length, buf->start);

    TEAX_DEBUG(buf->start,buf->size);

    memcpy(buf_append(buf,SEQLEN), nonce, SEQLEN);

    TEAX_DEBUG(nonce,SEQLEN);

    ti->sendseq++;

    return 0;
}

static uint32_t transform_reverse(void *sst, struct buffer_if *buf,
				  const char **errmsg)
{
    struct transform_inst *ti=sst;

    KEYED_CHECK;

    TEAX_DEBUG(buf->start,buf->size);

    uint8_t nonce[SEQLEN+1];
    const uint8_t *seqp = buf_unappend(buf,SEQLEN);
    if (!seqp) goto too_short;

    TEAX_DEBUG(seqp,SEQLEN);

    uint32_t seqnum = get_uint32(seqp);

    memcpy(nonce,seqp,SEQLEN);
    nonce[4] = !ti->direction;

    TEAX_DEBUG(nonce,sizeof(nonce));
    TEAX_DEBUG(buf->start,buf->size);

    bool_t ok = eax_decrypt(ti, nonce,sizeof(nonce), 0,0, buf->start,buf->size,
			    ti->p.tag_length, buf->start);
    if (!ok) {
	TEAX_DEBUG(0,0);
	*errmsg="EAX decryption failed";
	return 1;
    }
    assert(buf->size >= (int)ti->p.tag_length);
    buf->size -= ti->p.tag_length;

    TEAX_DEBUG(buf->start,buf->size);

    const uint8_t *padp = buf_unappend(buf,1);
    if (!padp) goto too_short;

    TEAX_DEBUG(padp,1);

    size_t padlen = *padp;
    if (!buf_unappend(buf,padlen-1)) goto too_short;

    SEQNUM_CHECK(seqnum, ti->p.max_seq_skew);

    TEAX_DEBUG(buf->start,buf->size);

    return 0;

 too_short:
    *errmsg="ciphertext or plaintext too short";
    return 1;
}

static struct transform_inst_if *transform_create(void *sst)
{
    struct transform *st=sst;

    TRANSFORM_CREATE_CORE;

    ti->p=st->p;

    return &ti->ops;
}

static list_t *transform_apply(closure_t *self, struct cloc loc,
			       dict_t *context, list_t *args)
{
    struct transform *st;
    item_t *item;
    dict_t *dict;

    st=safe_malloc(sizeof(*st),"eax-serpent");
    st->cl.description="eax-serpent";
    st->cl.type=CL_TRANSFORM;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;

    /* First parameter must be a dict */
    item=list_elem(args,0);
    if (!item || item->type!=t_dict)
	cfgfatal(loc,"eax-serpent","parameter must be a dictionary\n");
    dict=item->data.dict;

    SET_CAPAB_TRANSFORMNUM(CAPAB_TRANSFORMNUM_EAXSERPENT);

    st->p.max_seq_skew=dict_read_number(dict, "max-sequence-skew",
					False, "eax-serpent", loc, 10);

    st->p.tag_length=dict_read_number(dict, "tag-length-bytes",
				      False, "eax-serpent", loc, 128/8);
    if (st->p.tag_length<1 || st->p.tag_length>BLOCK_SIZE)
	cfgfatal(loc,"eax-serpent","tag-length-bytes out of range 0..%d\n",
		 BLOCK_SIZE);

    uint32_t padding_round=dict_read_number(dict, "padding-rounding",
					    False, "eax-serpent", loc, 16);
    if (padding_round & (padding_round-1))
	cfgfatal(loc,"eax-serpent","padding-round not a power of two\n");
    if (padding_round > 255)
	cfgfatal(loc,"eax-serpent","padding-round must be 1..128\n");
    if (padding_round == 0)
	padding_round = 1;
    st->p.padding_mask = padding_round-1;

    update_max_start_pad(&transform_max_start_pad, 0);

    st->ops.keylen=0;
    st->ops.create=transform_create;

    return new_closure(&st->cl);
}

void transform_eax_module(dict_t *dict)
{
    add_closure(dict,"eax-serpent",transform_apply);
}
