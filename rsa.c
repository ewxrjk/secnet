/*
 * rsa.c: implementation of RSA with PKCS#1 padding
 */
/*
 * This file is Free Software.  It was originally written for secnet.
 *
 * Copyright 1995-2003 Stephen Early
 * Copyright 2002-2014 Ian Jackson
 * Copyright 2001      Simon Tatham
 * Copyright 2013      Mark Wooding
 *
 * You may redistribute secnet as a whole and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3, or (at your option) any
 * later version.
 *
 * You may redistribute this file and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later
 * version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, see
 * https://www.gnu.org/licenses/gpl.html.
 */


#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "secnet.h"
#include "util.h"
#include "unaligned.h"

#define AUTHFILE_ID_STRING "SSH PRIVATE KEY FILE FORMAT 1.1\n"

#define mpp(s,n) do { char *p = mpz_get_str(NULL,16,n); printf("%s 0x%sL\n", s, p); free(p); } while (0)

struct rsacommon {
    uint8_t *hashbuf;
};

#define FREE(b)                ({ free((b)); (b)=0; })

struct load_ctx {
    void (*verror)(struct load_ctx *l, struct cloc loc,
		   FILE *maybe_f,
		   const char *message, va_list args);
    bool_t (*postreadcheck)(struct load_ctx *l, FILE *f);
    const char *what;
    dict_t *deprdict; /* used only to look up hash */
    struct cloc loc;
    union {
	struct {
	    struct log_if *log;
	} tryload;
    } u;
};

static void load_err(struct load_ctx *l,
		     const struct cloc *maybe_loc, FILE *maybe_f,
		     const char *fmt, ...)
{
    va_list al;
    va_start(al,fmt);
    l->verror(l, maybe_loc ? *maybe_loc : l->loc, maybe_f,fmt,al);
    va_end(al);
}

FORMAT(printf,4,0)
static void verror_tryload(struct load_ctx *l, struct cloc loc,
			   FILE *maybe_f,
			   const char *message, va_list args)
{
    int class=M_ERR;
    slilog_part(l->u.tryload.log,class,"%s: ",l->what);
    vslilog(l->u.tryload.log,class,message,args);
}

static void verror_cfgfatal(struct load_ctx *l, struct cloc loc,
			    FILE *maybe_f,
			    const char *message, va_list args)
{
    vcfgfatal_maybefile(maybe_f,l->loc,l->what,message,args,"");
}

struct rsapriv {
    closure_t cl;
    struct sigprivkey_if ops;
    struct cloc loc;
    struct rsacommon common;
    MP_INT n;
    MP_INT p, dp;
    MP_INT q, dq;
    MP_INT w;
};

#define RSAPUB_BNS(each)			\
    each(0,e,"public exponent")			\
    each(1,n,"modulus")

#define RSAPUB_LOADCORE_PASSBN(ix,en,what) \
    en##s, en##_loc,

#define RSAPUB_INIT_ST_BN( ix,en,what) mpz_init (&st->en);
#define RSAPUB_CLEAR_ST_BN(ix,en,what) mpz_clear(&st->en);

struct rsapub {
    closure_t cl;
    struct sigpubkey_if ops;
    struct cloc loc;
    struct rsacommon common;
    MP_INT e;
    MP_INT n;
};
/* Sign data. NB data must be smaller than modulus */

#define RSA_MAX_MODBYTES 2048
/* The largest modulus I've seen is 15360 bits, which works out at 1920
 * bytes.  Using keys this big is quite implausible, but it doesn't cost us
 * much to support them.
 */

static const char *hexchars="0123456789abcdef";

static void rsa_sethash(struct load_ctx *l,
			struct rsacommon *c,
			const struct hash_if **in_ops)
{
    struct hash_if *hash=0;
    if (l->deprdict)
	hash=find_cl_if(l->deprdict,"hash",CL_HASH,False,"site",l->loc);
    if (!hash)
	hash=sha1_hash_if;
    c->hashbuf=safe_malloc(hash->hlen, "generate_msg");
    *in_ops=hash;
}

static void rsacommon_dispose(struct rsacommon *c)
{
    free(c->hashbuf);
}

static void emsa_pkcs1(MP_INT *n, MP_INT *m,
		       const uint8_t *data, int32_t datalen)
{
    char buff[2*RSA_MAX_MODBYTES + 1];
    int msize, i;

    /* RSA PKCS#1 v1.5 signature padding:
     *
     * <------------ msize hex digits ---------->
     *
     * 00 01 ff ff .... ff ff 00 vv vv vv .... vv
     *
     *                           <--- datalen -->
     *                                 bytes
     *                         = datalen*2 hex digits
     *
     * NB that according to PKCS#1 v1.5 we're supposed to include a
     * hash function OID in the data.  We don't do that (because we
     * don't have the hash function OID to hand here), thus violating
     * the spec in a way that affects interop but not security.
     *
     * -iwj 17.9.2002
     */

    msize=mpz_sizeinbase(n, 16);

    if (datalen*2+6>=msize) {
	fatal("rsa: message too big");
    }

    strcpy(buff,"0001");

    for (i=0; i<datalen; i++) {
	buff[msize+(-datalen+i)*2]=hexchars[(data[i]&0xf0)>>4];
	buff[msize+(-datalen+i)*2+1]=hexchars[data[i]&0xf];
    }
    
    buff[msize-datalen*2-2]= '0';
    buff[msize-datalen*2-1]= '0';
 
    for (i=4; i<msize-datalen*2-2; i++)
       buff[i]='f';

    buff[msize]=0;

    mpz_set_str(m, buff, 16);
}

static bool_t rsa_sign(void *sst, uint8_t *data, int32_t datalen,
		       struct buffer_if *msg)
{
    struct rsapriv *st=sst;
    MP_INT a, b, u, v, tmp, tmp2;
    string_t signature = 0;
    bool_t ok;

    mpz_init(&a);
    mpz_init(&b);

    hash_hash(st->ops.hash,data,datalen,st->common.hashbuf);
    /* Construct the message representative. */
    emsa_pkcs1(&st->n, &a, st->common.hashbuf, st->ops.hash->hlen);

    /*
     * Produce an RSA signature (a^d mod n) using the Chinese
     * Remainder Theorem. We compute:
     * 
     *   u = a^dp mod p    (== a^d mod p, since dp == d mod (p-1))
     *   v = a^dq mod q    (== a^d mod q, similarly)
     * 
     * We also know w == iqmp * q, which has the property that w ==
     * 0 mod q and w == 1 mod p. So (1-w) has the reverse property
     * (congruent to 0 mod p and to 1 mod q). Hence we now compute
     * 
     *   b = w * u + (1-w) * v
     *     = w * (u-v) + v
     * 
     * so that b is congruent to a^d both mod p and mod q. Hence b,
     * reduced mod n, is the required signature.
     */
    mpz_init(&tmp);
    mpz_init(&tmp2);
    mpz_init(&u);
    mpz_init(&v);

    mpz_powm_sec(&u, &a, &st->dp, &st->p);
    mpz_powm_sec(&v, &a, &st->dq, &st->q);
    mpz_sub(&tmp, &u, &v);
    mpz_mul(&tmp2, &tmp, &st->w);
    mpz_add(&tmp, &tmp2, &v);
    mpz_mod(&b, &tmp, &st->n);

    mpz_clear(&tmp);
    mpz_clear(&tmp2);
    mpz_clear(&u);
    mpz_clear(&v);

    signature=write_mpstring(&b);

    uint8_t *op = buf_append(msg,2);
    if (!op) { ok=False; goto out; }
    size_t l = strlen(signature);
    assert(l < 65536);
    put_uint16(op, l);
    op = buf_append(msg,l);
    if (!op) { ok=False; goto out; }
    memcpy(op, signature, l);

    ok = True;

 out:
    free(signature);
    mpz_clear(&b);
    mpz_clear(&a);
    return ok;
}

static bool_t rsa_sig_unpick(void *sst, struct buffer_if *msg,
			     struct alg_msg_data *sig)
{
    uint8_t *lp = buf_unprepend(msg, 2);
    if (!lp) return False;
    sig->len = get_uint16(lp);
    sig->start = buf_unprepend(msg, sig->len);
    if (!sig->start) return False;

    /* In `rsa_sig_check' below, we assume that we can write a nul
     * terminator following the signature.  Make sure there's enough space.
     */
    if (msg->start >= msg->base + msg->alloclen)
	return False;

    return True;
}

static sig_checksig_fn rsa_sig_check;
static bool_t rsa_sig_check(void *sst, uint8_t *data, int32_t datalen,
			    const struct alg_msg_data *sig)
{
    struct rsapub *st=sst;
    MP_INT a, b, c;
    bool_t ok;

    mpz_init(&a);
    mpz_init(&b);
    mpz_init(&c);

    hash_hash(st->ops.hash,data,datalen,st->common.hashbuf);
    emsa_pkcs1(&st->n, &a, st->common.hashbuf, st->ops.hash->hlen);

    /* Terminate signature with a '0' - already checked that this will fit */
    int save = sig->start[sig->len];
    sig->start[sig->len] = 0;
    mpz_set_str(&b, sig->start, 16);
    sig->start[sig->len] = save;

    mpz_powm(&c, &b, &st->e, &st->n);

    ok=(mpz_cmp(&a, &c)==0);

    mpz_clear(&c);
    mpz_clear(&b);
    mpz_clear(&a);

    return ok;
}

static void rsapub_dispose(void *sst) {
    struct rsapub *st=sst;

    if (!st) return;
    RSAPUB_BNS(RSAPUB_CLEAR_ST_BN)
    rsacommon_dispose(&st->common);
    free(st);
}

#define RSAPUB_LOADCORE_DEFBN(ix,en,what) \
    const char *en##s, struct cloc en##_loc,

#define LDPUBFATAL(lc,...) ({			\
	load_err(l,(lc),0,__VA_ARGS__);	\
	goto error_out;				\
    })

static struct rsapub *rsa_loadpub_core(RSAPUB_BNS(RSAPUB_LOADCORE_DEFBN)
				       struct load_ctx *l)
{
    struct rsapub *st;

    NEW(st);
    st->cl.description="rsapub";
    st->cl.type=CL_SIGPUBKEY;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->common.hashbuf=NULL;
    st->ops.unpick=rsa_sig_unpick;
    st->ops.check=rsa_sig_check;
    st->ops.hash=0;
    st->ops.dispose=rsapub_dispose;
    st->loc=l->loc;
    RSAPUB_BNS(RSAPUB_INIT_ST_BN)

#define RSAPUB_LOADCORE_GETBN(ix,en,what)				\
    if (mpz_init_set_str(&st->en,en##s,10)!=0) {			\
	LDPUBFATAL(&en##_loc, what " \"%s\" is not a "			\
		 "decimal number string",en##s);			\
    }									\
    if (mpz_sizeinbase(&st->en, 256) > RSA_MAX_MODBYTES) {		\
	LDPUBFATAL(&en##_loc, "implausibly large " what);		\
    }

    RSAPUB_BNS(RSAPUB_LOADCORE_GETBN)

    rsa_sethash(l,&st->common,&st->ops.hash);

    return st;

 error_out:
    rsapub_dispose(st);
    return 0;
}

static list_t *rsapub_apply(closure_t *self, struct cloc loc, dict_t *context,
			    list_t *args)
{
    struct load_ctx l[1];
    l->verror=verror_cfgfatal;
    l->postreadcheck=0;
    l->what="rsa-public";
    l->deprdict=context;
    l->loc=loc;

#define RSAPUB_APPLY_GETBN(ix,en,what)				\
    item_t *en##i;						\
    const char *en##s;						\
    en##i=list_elem(args,ix);					\
    if (!en##i)							\
        cfgfatal(loc,"rsa-public",				\
                 "you must provide an encryption key\n");	\
    struct cloc en##_loc=en##i->loc;				\
    if (en##i->type!=t_string)					\
	cfgfatal(en##_loc,"rsa-public",				\
		 "first argument must be a string\n");		\
    en##s=en##i->data.string;

    RSAPUB_BNS(RSAPUB_APPLY_GETBN)

    struct rsapub *st=rsa_loadpub_core(RSAPUB_BNS(RSAPUB_LOADCORE_PASSBN)
				       l);

    return new_closure(&st->cl);
}

bool_t rsa1_loadpub(const struct sigscheme_info *algo,
		    struct buffer_if *pubkeydata,
		    struct sigpubkey_if **sigpub_r,
		    closure_t **closure_r,
		    struct log_if *log, struct cloc loc)
{
    struct rsapub *st=0;

    struct load_ctx l[1];
    l->verror=verror_tryload;
    l->postreadcheck=0;
    l->what="rsa1_loadpub";
    l->deprdict=0;
    l->loc=loc;
    l->u.tryload.log=log;

    char *nul=buf_append(pubkeydata,1);
    if (!nul) LDPUBFATAL(0,"rsa1 public key data too long for extra nul");
    *nul=0;

    const char *delim=" \t\n";
    char *saveptr;
    /*unused*/ strtok_r(pubkeydata->start,delim,&saveptr);

#define RSAPUB_TRYLOAD_GETBN(ix,en,what)				\
    struct cloc en##_loc=loc;						\
    const char *en##s=strtok_r(0,delim,&saveptr);			\
    if (!en##s) LDPUBFATAL(0,"end of pubkey data looking for " what);

    RSAPUB_BNS(RSAPUB_TRYLOAD_GETBN);

    st=rsa_loadpub_core(RSAPUB_BNS(RSAPUB_LOADCORE_PASSBN) l);
    if (!st) goto error_out;

    *sigpub_r=&st->ops;
    *closure_r=&st->cl;
    return True;

 error_out:
    rsapub_dispose(st);
    return False;
}

#define LDFATAL(...)      ({ load_err(l,0,0,__VA_ARGS__); goto error_out; })
#define LDFATAL_FILE(...) ({ load_err(l,0,f,__VA_ARGS__); goto error_out; })
#define KEYFILE_GET(is)   ({					\
	uint##is##_t keyfile_get_tmp=keyfile_get_##is(l,f);	\
	if (!l->postreadcheck(l,f)) goto error_out;		\
	keyfile_get_tmp;					\
    })

static uint32_t keyfile_get_32(struct load_ctx *l, FILE *f)
{
    uint32_t r;
    r=fgetc(f)<<24;
    r|=fgetc(f)<<16;
    r|=fgetc(f)<<8;
    r|=fgetc(f);
    return r;
}

static uint16_t keyfile_get_16(struct load_ctx *l, FILE *f)
{
    uint16_t r;
    r=fgetc(f)<<8;
    r|=fgetc(f);
    return r;
}

static void rsapriv_dispose(void *sst)
{
    struct rsapriv *st=sst;
    mpz_clear(&st->n);
    mpz_clear(&st->p); mpz_clear(&st->dp);
    mpz_clear(&st->q); mpz_clear(&st->dq);
    mpz_clear(&st->w);
    rsacommon_dispose(&st->common);
    free(st);
}

static struct rsapriv *rsa_loadpriv_core(struct load_ctx *l,
					 FILE *f, struct cloc loc,
					 bool_t do_validity_check)
{
    struct rsapriv *st=0;
    long length;
    uint8_t *b=0, *c=0;
    int cipher_type;
    MP_INT e,d,iqmp,tmp,tmp2,tmp3;
    bool_t valid;

    mpz_init(&e);
    mpz_init(&d);
    mpz_init(&iqmp);
    mpz_init(&tmp);
    mpz_init(&tmp2);
    mpz_init(&tmp3);

    NEW(st);
    st->cl.description="rsapriv";
    st->cl.type=CL_SIGPRIVKEY;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->common.hashbuf=NULL;
    st->ops.sign=rsa_sign;
    st->ops.hash=0;
    st->ops.dispose=rsapriv_dispose;
    st->loc=loc;
    mpz_init(&st->n);
    mpz_init(&st->q);
    mpz_init(&st->p);
    mpz_init(&st->dp);
    mpz_init(&st->dq);
    mpz_init(&st->w);

    if (!f) {
	assert(just_check_config);
	goto assume_valid;
    }

    /* Check that the ID string is correct */
    length=strlen(AUTHFILE_ID_STRING)+1;
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f)!=1 || memcmp(b,AUTHFILE_ID_STRING,length)!=0) {
	LDFATAL_FILE("failed to read magic ID"
		     " string from SSH1 private keyfile\n");
    }
    FREE(b);

    cipher_type=fgetc(f);
    KEYFILE_GET(32); /* "Reserved data" */
    if (cipher_type != 0) {
	LDFATAL("we don't support encrypted keyfiles\n");
    }

    /* Read the public key */
    KEYFILE_GET(32); /* Not sure what this is */
    length=(KEYFILE_GET(16)+7)/8;
    if (length>RSA_MAX_MODBYTES) {
	LDFATAL("implausible length %ld for modulus\n",
		 length);
    }
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f) != 1) {
	LDFATAL_FILE("error reading modulus\n");
    }
    read_mpbin(&st->n,b,length);
    FREE(b);
    length=(KEYFILE_GET(16)+7)/8;
    if (length>RSA_MAX_MODBYTES) {
	LDFATAL("implausible length %ld for e\n",length);
    }
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f)!=1) {
	LDFATAL_FILE("error reading e\n");
    }
    read_mpbin(&e,b,length);
    FREE(b);
    
    length=KEYFILE_GET(32);
    if (length>1024) {
	LDFATAL("implausibly long (%ld) key comment\n",
		 length);
    }
    c=safe_malloc(length+1,"rsapriv_apply");
    if (fread(c,length,1,f)!=1) {
	LDFATAL_FILE("error reading key comment\n");
    }
    c[length]=0;

    /* Check that the next two pairs of characters are identical - the
       keyfile is not encrypted, so they should be */

    if (KEYFILE_GET(16) != KEYFILE_GET(16)) {
	LDFATAL("corrupt keyfile\n");
    }

    /* Read d */
    length=(KEYFILE_GET(16)+7)/8;
    if (length>RSA_MAX_MODBYTES) {
	LDFATAL("implausibly long (%ld) decryption key\n",
		 length);
    }
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f)!=1) {
	LDFATAL_FILE("error reading decryption key\n");
    }
    read_mpbin(&d,b,length);
    FREE(b);
    /* Read iqmp (inverse of q mod p) */
    length=(KEYFILE_GET(16)+7)/8;
    if (length>RSA_MAX_MODBYTES) {
	LDFATAL("implausibly long (%ld)"
		 " iqmp auxiliary value\n", length);
    }
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f)!=1) {
	LDFATAL_FILE("error reading decryption key\n");
    }
    read_mpbin(&iqmp,b,length);
    FREE(b);
    /* Read q (the smaller of the two primes) */
    length=(KEYFILE_GET(16)+7)/8;
    if (length>RSA_MAX_MODBYTES) {
	LDFATAL("implausibly long (%ld) q value\n",
		 length);
    }
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f)!=1) {
	LDFATAL_FILE("error reading q value\n");
    }
    read_mpbin(&st->q,b,length);
    FREE(b);
    /* Read p (the larger of the two primes) */
    length=(KEYFILE_GET(16)+7)/8;
    if (length>RSA_MAX_MODBYTES) {
	LDFATAL("implausibly long (%ld) p value\n",
		 length);
    }
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f)!=1) {
	LDFATAL_FILE("error reading p value\n");
    }
    read_mpbin(&st->p,b,length);
    FREE(b);
    
    if (ferror(f)) {
	fatal_perror("rsa-private (%s:%d): ferror",loc.file,loc.line);
    }

    rsa_sethash(l,&st->common,&st->ops.hash);

    /*
     * Now verify the validity of the key, and set up the auxiliary
     * values for fast CRT signing.
     */
    valid=False;
    if (do_validity_check) {
	/* Verify that p*q is equal to n. */
	mpz_mul(&tmp, &st->p, &st->q);
	if (mpz_cmp(&tmp, &st->n) != 0)
	    goto done_checks;

	/*
	 * Verify that d*e is congruent to 1 mod (p-1), and mod
	 * (q-1). This is equivalent to it being congruent to 1 mod
	 * lambda(n) = lcm(p-1,q-1).  The usual `textbook' condition,
	 * that d e == 1 (mod (p-1)(q-1)) is sufficient, but not
	 * actually necessary.
	 */
	mpz_mul(&tmp, &d, &e);
	mpz_sub_ui(&tmp2, &st->p, 1);
	mpz_mod(&tmp3, &tmp, &tmp2);
	if (mpz_cmp_si(&tmp3, 1) != 0)
	    goto done_checks;
	mpz_sub_ui(&tmp2, &st->q, 1);
	mpz_mod(&tmp3, &tmp, &tmp2);
	if (mpz_cmp_si(&tmp3, 1) != 0)
	    goto done_checks;

	/* Verify that q*iqmp is congruent to 1 mod p. */
	mpz_mul(&tmp, &st->q, &iqmp);
	mpz_mod(&tmp2, &tmp, &st->p);
	if (mpz_cmp_si(&tmp2, 1) != 0)
	    goto done_checks;
    }
    /* Now we know the key is valid (or we don't care). */
    valid = True;
    
    /*
     * Now we compute auxiliary values dp, dq and w to allow us
     * to use the CRT optimisation when signing.
     * 
     *   dp == d mod (p-1)      so that a^dp == a^d mod p, for all a
     *   dq == d mod (q-1)      similarly mod q
     *   w == iqmp * q          so that w == 0 mod q, and w == 1 mod p
     */
    mpz_sub_ui(&tmp, &st->p, 1);
    mpz_mod(&st->dp, &d, &tmp);
    mpz_sub_ui(&tmp, &st->q, 1);
    mpz_mod(&st->dq, &d, &tmp);
    mpz_mul(&st->w, &iqmp, &st->q);
    
done_checks:
    if (!valid) {
	LDFATAL("file does not contain a "
		 "valid RSA key!\n");
    }

assume_valid:
out:
    mpz_clear(&tmp);
    mpz_clear(&tmp2);
    mpz_clear(&tmp3);

    FREE(b);
    FREE(c);
    mpz_clear(&e);
    mpz_clear(&d);
    mpz_clear(&iqmp);

    return st;

error_out:
    if (st) rsapriv_dispose(st);
    st=0;
    goto out;
}

static bool_t postreadcheck_tryload(struct load_ctx *l, FILE *f)
{
    assert(!ferror(f));
    if (feof(f)) { load_err(l,0,0,"eof mid-integer"); return False; }
    return True;
}

bool_t rsa1_loadpriv(const struct sigscheme_info *algo,
		     struct buffer_if *privkeydata,
		     struct sigprivkey_if **sigpriv_r,
		     closure_t **closure_r,
		     struct log_if *log, struct cloc loc)
{
    FILE *f=0;
    struct rsapriv *st=0;

    f=fmemopen(privkeydata->start,privkeydata->size,"r");
    if (!f) {
	slilog(log,M_ERR,"failed to fmemopen private key file\n");
	goto error_out;
    }

    struct load_ctx l[1];
    l->what="rsa1priv load";
    l->verror=verror_tryload;
    l->postreadcheck=postreadcheck_tryload;
    l->deprdict=0;
    l->loc=loc;
    l->u.tryload.log=log;

    st=rsa_loadpriv_core(l,f,loc,False);
    if (!st) goto error_out;
    goto out;

 error_out:
    FREE(st);
 out:
    if (f) fclose(f);
    if (!st) return False;
    *sigpriv_r=&st->ops;
    *closure_r=&st->cl;
    return True;
}

static bool_t postreadcheck_apply(struct load_ctx *l, FILE *f)
{
    cfgfile_postreadcheck(l->loc,f);
    return True;
}

static list_t *rsapriv_apply(closure_t *self, struct cloc loc, dict_t *context,
			     list_t *args)
{
    struct rsapriv *st;
    item_t *i;
    cstring_t filename;
    FILE *f;
    struct load_ctx l[1];

    l->what="rsa-private";
    l->verror=verror_cfgfatal;
    l->postreadcheck=postreadcheck_apply;
    l->deprdict=context;
    l->loc=loc;

    /* Argument is filename pointing to SSH1 private key file */
    i=list_elem(args,0);
    if (i) {
	if (i->type!=t_string) {
	    cfgfatal(i->loc,"rsa-private","first argument must be a string\n");
	}
	filename=i->data.string;
    } else {
	filename=NULL; /* Make compiler happy */
	cfgfatal(i->loc,"rsa-private","you must provide a filename\n");
    }

    f=fopen(filename,"rb");
    if (!f) {
	if (just_check_config) {
	    Message(M_WARNING,"rsa-private (%s:%d): cannot open keyfile "
		    "\"%s\" (%s); assuming it's valid while we check the "
		    "rest of the configuration\n",
		    loc.file,loc.line,filename,strerror(errno));
	    return list_new();
	} else {
	    fatal_perror("rsa-private (%s:%d): cannot open file \"%s\"",
			 loc.file,loc.line,filename);
	}
    }

    bool_t do_validity_check=True;
    i=list_elem(args,1);
    if (i && i->type==t_bool && i->data.bool==False) {
	Message(M_INFO,"rsa-private (%s:%d): skipping RSA key validity "
		"check\n",loc.file,loc.line);
	do_validity_check=False;
    }

    st=rsa_loadpriv_core(l,f,loc,do_validity_check);
    fclose(f);
    return new_closure(&st->cl);
}

void rsa_module(dict_t *dict)
{
    add_closure(dict,"rsa-private",rsapriv_apply);
    add_closure(dict,"rsa-public",rsapub_apply);
}
