/* Transform module - bulk data transformation */

/* For now it's hard-coded to do sequence
   number/pkcs5/serpent-cbcmac/serpent with a 256 bit key for each
   instance of serpent. We also require key material for the IVs for
   cbcmac and cbc. Hack: we're not using full 128-bit IVs, we're just
   using 32 bits and encrypting to get the full IV to save space in
   the packets sent over the wire. */

#include <stdio.h>
#include "secnet.h"
#include "util.h"
#include "serpent.h"

/* Required key length in bytes */
#define REQUIRED_KEYLEN ((512+64+32)/8)

struct transform {
    closure_t cl;
    uint32_t line;
    struct transform_if ops;
    uint32_t max_seq_skew;
};

struct transform_inst {
    struct transform_inst_if ops;
    struct keyInstance cryptkey;
    struct keyInstance mackey;
    uint32_t cryptiv;
    uint32_t maciv;
    uint32_t sendseq;
    uint32_t lastrecvseq;
    uint32_t max_skew;
    bool_t keyed;
};

#define PKCS5_MASK 15

static bool_t transform_setkey(void *sst, uint8_t *key, uint32_t keylen)
{
    struct transform_inst *ti=sst;

    if (keylen<REQUIRED_KEYLEN) {
	Message(M_ERROR,"transform_create: insufficient key material supplied "
		"(need %d bytes, got %d)\n",REQUIRED_KEYLEN,keylen);
	return False;
    }

#if 0
    {
	int i;
	printf("Setting key to: ");
	for (i=0; i<keylen; i++)
	    printf("%02x",key[i]);
	printf("\n");
    }
#endif /* 0 */

    serpent_makekey(&ti->cryptkey,256,key);
    serpent_makekey(&ti->mackey,256,key+32);
    ti->cryptiv=*(uint32_t *)(key+64);
    ti->maciv=*(uint32_t *)(key+68);
    ti->sendseq=*(uint32_t *)(key+72);
    ti->lastrecvseq=ti->sendseq;
    ti->keyed=True;

    return True;
}

static void transform_delkey(void *sst)
{
    struct transform_inst *ti=sst;

    memset(&ti->cryptkey,0,sizeof(ti->cryptkey));
    memset(&ti->mackey,0,sizeof(ti->mackey));
    ti->keyed=False;
}

static uint32_t transform_forward(void *sst, struct buffer_if *buf,
				  char **errmsg)
{
    struct transform_inst *ti=sst;
    uint8_t *padp;
    int padlen;
    uint32_t iv[4];
    uint32_t macplain[4];
    uint32_t macacc[4];
    uint32_t *n, *p;

    if (!ti->keyed) {
	*errmsg="transform unkeyed";
	return 1;
    }

    /* Sequence number */
    *(uint32_t *)buf_prepend(buf,4)=htonl(ti->sendseq);
    ti->sendseq++;

    /* PKCS5, stolen from IWJ */
                                    /* eg with blocksize=4 mask=3 mask+2=5   */
                                    /* msgsize    20    21    22    23   24  */
    padlen= PKCS5_MASK-buf->size;   /*           -17   -18   -19   -16  -17  */
    padlen &= PKCS5_MASK;           /*             3     2     1     0    3  */
    padlen++;                       /*             4     3     2     1    4  */

    padp=buf_append(buf,padlen);
    memset(padp,padlen,padlen);

    /* Serpent-CBCMAC. We expand the IV from 32-bit to 128-bit using
       one encryption. Then we do the MAC and append the result. We don't
       bother sending the IV - it's the same each time. (If we wanted to send
       it we've have to add 16 bytes to each message, not 4, so that the
       message stays a multiple of 16 bytes long.) */
    memset(iv,0,16);
    iv[0]=ti->maciv;
    serpent_encrypt(&ti->mackey,iv,macacc);

    /* CBCMAC: encrypt in CBC mode. The MAC is the last encrypted
       block encrypted once again. */
    for (n=(uint32_t *)buf->start; n<(uint32_t *)(buf->start+buf->size); n+=4)
    {
	macplain[0]=macacc[0]^n[0];
	macplain[1]=macacc[1]^n[1];
	macplain[2]=macacc[2]^n[2];
	macplain[3]=macacc[3]^n[3];
	serpent_encrypt(&ti->mackey,macplain,macacc);
    }
    serpent_encrypt(&ti->mackey,macacc,macacc);
    memcpy(buf_append(buf,16),macacc,16);

    /* Serpent-CBC. We expand the ID as for CBCMAC, do the encryption,
       and prepend the IV before increasing it. */
    memset(iv,0,16);
    iv[0]=ti->cryptiv;
    serpent_encrypt(&ti->cryptkey,iv,iv);

    /* CBC: each block is XORed with the previous encrypted block (or the IV)
       before being encrypted. */
    p=iv;
    for (n=(uint32_t *)buf->start; n<(uint32_t *)(buf->start+buf->size); n+=4)
    {
	n[0]=p[0]^n[0];
	n[1]=p[1]^n[1];
	n[2]=p[2]^n[2];
	n[3]=p[3]^n[3];
	serpent_encrypt(&ti->cryptkey,n,n);
	p=n;
    }

    *(uint32_t *)buf_prepend(buf,4)=ti->cryptiv;
    ti->cryptiv++;

    return 0;
}

static uint32_t transform_reverse(void *sst, struct buffer_if *buf,
				  char **errmsg)
{
    struct transform_inst *ti=sst;
    uint8_t *padp;
    unsigned padlen;
    int i;
    uint32_t seqnum, skew;
    uint32_t iv[4];
    uint32_t pct[4];
    uint32_t macplain[4];
    uint32_t macacc[4];
    uint32_t *n;
    uint32_t *macexpected;

    if (!ti->keyed) {
	*errmsg="transform unkeyed";
	return 1;
    }

    /* CBC */
    memset(iv,0,16);
    iv[0]=*(uint32_t *)buf_unprepend(buf,4);
    serpent_encrypt(&ti->cryptkey,iv,iv);
    /* XXX assert bufsize is multiple of blocksize */
    for (n=(uint32_t *)buf->start; n<(uint32_t *)(buf->start+buf->size); n+=4)
    {
	pct[0]=n[0]; pct[1]=n[1]; pct[2]=n[2]; pct[3]=n[3];
	serpent_decrypt(&ti->cryptkey,n,n);
	n[0]=iv[0]^n[0];
	n[1]=iv[1]^n[1];
	n[2]=iv[2]^n[2];
	n[3]=iv[3]^n[3];
	iv[0]=pct[0]; iv[1]=pct[1]; iv[2]=pct[2]; iv[3]=pct[3];
    }

    /* CBCMAC */
    macexpected=buf_unappend(buf,16);
    memset(iv,0,16);
    iv[0]=ti->maciv;
    serpent_encrypt(&ti->mackey,iv,macacc);

    /* CBCMAC: encrypt in CBC mode. The MAC is the last encrypted
       block encrypted once again. */
    for (n=(uint32_t *)buf->start; n<(uint32_t *)(buf->start+buf->size); n+=4)
    {
	macplain[0]=macacc[0]^n[0];
	macplain[1]=macacc[1]^n[1];
	macplain[2]=macacc[2]^n[2];
	macplain[3]=macacc[3]^n[3];
	serpent_encrypt(&ti->mackey,macplain,macacc);
    }
    serpent_encrypt(&ti->mackey,macacc,macacc);
    if (memcmp(macexpected,macacc,16)!=0) {
	*errmsg="invalid MAC";
	return 1;
    }

    /* PKCS5, stolen from IWJ */

    padp=buf_unappend(buf,1);
    padlen=*padp;
    if (!padlen || (padlen > PKCS5_MASK+1)) {
	*errmsg="pkcs5: invalid length";
	return 1;
    }

    padp=buf_unappend(buf,padlen-1);
    for (i=0; i<padlen-1; i++) {
	if (*++padp != padlen) {
	    *errmsg="pkcs5: corrupted padding";
	    return 1;
	}
    }

    /* Sequence number must be within max_skew of lastrecvseq; lastrecvseq
       is only allowed to increase. */
    seqnum=ntohl(*(uint32_t *)buf_unprepend(buf,4));
    skew=seqnum-ti->lastrecvseq;
    if (skew<10) {
	/* Ok */
	ti->lastrecvseq=seqnum;
    } else if ((0-skew)<10) {
	/* Ok */
    } else {
	/* Too much skew */
	*errmsg="seqnum: too much skew";
	return 1;
    }
    
    return 0;
}

static void transform_destroy(void *sst)
{
    struct transform_inst *st=sst;

    memset(st,0,sizeof(*st)); /* Destroy key material */
    free(st);
}

static struct transform_inst_if *transform_create(void *sst)
{
    struct transform_inst *ti;
    struct transform *st=sst;

    ti=safe_malloc(sizeof(*ti),"transform_create");
    /* mlock XXX */

    ti->ops.st=ti;
    ti->ops.setkey=transform_setkey;
    ti->ops.delkey=transform_delkey;
    ti->ops.forwards=transform_forward;
    ti->ops.reverse=transform_reverse;
    ti->ops.destroy=transform_destroy;
    ti->max_skew=st->max_seq_skew;
    ti->keyed=False;

    return &ti->ops;
}

static list_t *transform_apply(closure_t *self, struct cloc loc,
			       dict_t *context, list_t *args)
{
    struct transform *st;
    item_t *item;
    dict_t *dict;

    st=safe_malloc(sizeof(*st),"serpent");
    st->cl.description="serpent-cbc256";
    st->cl.type=CL_TRANSFORM;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.max_start_pad=28; /* 4byte seqnum, 16byte pad, 4byte MACIV,
				 4byte IV */
    st->ops.max_end_pad=16; /* 16byte CBCMAC */

    /* We need 256*2 bits for serpent keys, 32 bits for CBC-IV and 32 bits
       for CBCMAC-IV, and 32 bits for init sequence number */
    st->ops.keylen=REQUIRED_KEYLEN;
    st->ops.create=transform_create;

    /* First parameter must be a dict */
    item=list_elem(args,0);
    if (!item || item->type!=t_dict)
	cfgfatal(loc,"userv-ipif","parameter must be a dictionary\n");
    
    dict=item->data.dict;
    st->max_seq_skew=dict_read_number(dict, "max-sequence-skew",
				      False, "serpent-cbc256", loc, 10);

    return new_closure(&st->cl);
}

init_module transform_module;
void transform_module(dict_t *dict)
{
    struct keyInstance k;
    uint8_t data[32];
    uint32_t plaintext[4];
    uint32_t ciphertext[4];

    /* Serpent self-test */
    memset(data,0,32);
    serpent_makekey(&k,256,data);
    plaintext[0]=0x00000000;
    plaintext[1]=0x00000001;
    plaintext[2]=0x00000002;
    plaintext[3]=0x00000003;
    serpent_encrypt(&k,plaintext,ciphertext);
    if (ciphertext[3]!=0x7ca73bb0 ||
	ciphertext[2]!=0x83C31E69 ||
	ciphertext[1]!=0xec52bd82 ||
	ciphertext[0]!=0x27a46120) {
	fatal("transform_module: serpent failed self-test (encrypt)\n");
    }
    serpent_decrypt(&k,ciphertext,plaintext);
    if (plaintext[0]!=0 ||
	plaintext[1]!=1 ||
	plaintext[2]!=2 ||
	plaintext[3]!=3) {
	fatal("transform_module: serpent failed self-test (decrypt)\n");
    }

    add_closure(dict,"serpent256-cbc",transform_apply);
}
