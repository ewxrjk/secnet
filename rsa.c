/* This file is part of secnet, and is distributed under the terms of
   the GNU General Public License version 2 or later.

   Copyright (C) 1995-2002 Stephen Early
   Copyright (C) 2001 Simon Tatham
   Copyright (C) 2002 Ian Jackson
   */

#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "secnet.h"
#include "util.h"

#define AUTHFILE_ID_STRING "SSH PRIVATE KEY FILE FORMAT 1.1\n"

#define mpp(s,n) do { char *p = mpz_get_str(NULL,16,n); printf("%s 0x%sL\n", s, p); free(p); } while (0)

struct rsapriv {
    closure_t cl;
    struct rsaprivkey_if ops;
    struct cloc loc;
    MP_INT n;
    MP_INT p, dp;
    MP_INT q, dq;
    MP_INT w;
};
struct rsapub {
    closure_t cl;
    struct rsapubkey_if ops;
    struct cloc loc;
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
	fatal("rsa_sign: message too big");
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

static string_t rsa_sign(void *sst, uint8_t *data, int32_t datalen)
{
    struct rsapriv *st=sst;
    MP_INT a, b, u, v, tmp, tmp2;
    string_t signature;

    mpz_init(&a);
    mpz_init(&b);

    /* Construct the message representative. */
    emsa_pkcs1(&st->n, &a, data, datalen);

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

    mpz_powm(&u, &a, &st->dp, &st->p);
    mpz_powm(&v, &a, &st->dq, &st->q);
    mpz_sub(&tmp, &u, &v);
    mpz_mul(&tmp2, &tmp, &st->w);
    mpz_add(&tmp, &tmp2, &v);
    mpz_mod(&b, &tmp, &st->n);

    mpz_clear(&tmp);
    mpz_clear(&tmp2);
    mpz_clear(&u);
    mpz_clear(&v);

    signature=write_mpstring(&b);

    mpz_clear(&b);
    mpz_clear(&a);
    return signature;
}

static rsa_checksig_fn rsa_sig_check;
static bool_t rsa_sig_check(void *sst, uint8_t *data, int32_t datalen,
			    cstring_t signature)
{
    struct rsapub *st=sst;
    MP_INT a, b, c;
    bool_t ok;

    mpz_init(&a);
    mpz_init(&b);
    mpz_init(&c);

    emsa_pkcs1(&st->n, &a, data, datalen);

    mpz_set_str(&b, signature, 16);

    mpz_powm(&c, &b, &st->e, &st->n);

    ok=(mpz_cmp(&a, &c)==0);

    mpz_clear(&c);
    mpz_clear(&b);
    mpz_clear(&a);

    return ok;
}

static list_t *rsapub_apply(closure_t *self, struct cloc loc, dict_t *context,
			    list_t *args)
{
    struct rsapub *st;
    item_t *i;
    string_t e,n;

    st=safe_malloc(sizeof(*st),"rsapub_apply");
    st->cl.description="rsapub";
    st->cl.type=CL_RSAPUBKEY;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.check=rsa_sig_check;
    st->loc=loc;

    i=list_elem(args,0);
    if (i) {
	if (i->type!=t_string) {
	    cfgfatal(i->loc,"rsa-public","first argument must be a string\n");
	}
	e=i->data.string;
	if (mpz_init_set_str(&st->e,e,10)!=0) {
	    cfgfatal(i->loc,"rsa-public","encryption key \"%s\" is not a "
		     "decimal number string\n",e);
	}
    } else {
	cfgfatal(loc,"rsa-public","you must provide an encryption key\n");
    }
    if (mpz_sizeinbase(&st->e, 256) > RSA_MAX_MODBYTES) {
	cfgfatal(loc, "rsa-public", "implausibly large public exponent\n");
    }
    
    i=list_elem(args,1);
    if (i) {
	if (i->type!=t_string) {
	    cfgfatal(i->loc,"rsa-public","second argument must be a string\n");
	}
	n=i->data.string;
	if (mpz_init_set_str(&st->n,n,10)!=0) {
	    cfgfatal(i->loc,"rsa-public","modulus \"%s\" is not a decimal "
		     "number string\n",n);
	}
    } else {
	cfgfatal(loc,"rsa-public","you must provide a modulus\n");
    }
    if (mpz_sizeinbase(&st->n, 256) > RSA_MAX_MODBYTES) {
	cfgfatal(loc, "rsa-public", "implausibly large modulus\n");
    }
    return new_closure(&st->cl);
}

static uint32_t keyfile_get_int(struct cloc loc, FILE *f)
{
    uint32_t r;
    r=fgetc(f)<<24;
    r|=fgetc(f)<<16;
    r|=fgetc(f)<<8;
    r|=fgetc(f);
    cfgfile_postreadcheck(loc,f);
    return r;
}

static uint16_t keyfile_get_short(struct cloc loc, FILE *f)
{
    uint16_t r;
    r=fgetc(f)<<8;
    r|=fgetc(f);
    cfgfile_postreadcheck(loc,f);
    return r;
}

static list_t *rsapriv_apply(closure_t *self, struct cloc loc, dict_t *context,
			     list_t *args)
{
    struct rsapriv *st;
    FILE *f;
    cstring_t filename;
    item_t *i;
    long length;
    uint8_t *b, *c;
    int cipher_type;
    MP_INT e,d,iqmp,tmp,tmp2,tmp3;
    bool_t valid;

    st=safe_malloc(sizeof(*st),"rsapriv_apply");
    st->cl.description="rsapriv";
    st->cl.type=CL_RSAPRIVKEY;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.sign=rsa_sign;
    st->loc=loc;

    /* Argument is filename pointing to SSH1 private key file */
    i=list_elem(args,0);
    if (i) {
	if (i->type!=t_string) {
	    cfgfatal(i->loc,"rsa-public","first argument must be a string\n");
	}
	filename=i->data.string;
    } else {
	filename=NULL; /* Make compiler happy */
	cfgfatal(loc,"rsa-private","you must provide a filename\n");
    }

    f=fopen(filename,"rb");
    if (!f) {
	if (just_check_config) {
	    Message(M_WARNING,"rsa-private (%s:%d): cannot open keyfile "
		    "\"%s\"; assuming it's valid while we check the "
		    "rest of the configuration\n",loc.file,loc.line,filename);
	    goto assume_valid;
	} else {
	    fatal_perror("rsa-private (%s:%d): cannot open file \"%s\"",
			 loc.file,loc.line,filename);
	}
    }

    /* Check that the ID string is correct */
    length=strlen(AUTHFILE_ID_STRING)+1;
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f)!=1 || memcmp(b,AUTHFILE_ID_STRING,length)!=0) {
	cfgfatal_maybefile(f,loc,"rsa-private","failed to read magic ID"
			   " string from SSH1 private keyfile \"%s\"\n",
			   filename);
    }
    free(b);

    cipher_type=fgetc(f);
    keyfile_get_int(loc,f); /* "Reserved data" */
    if (cipher_type != 0) {
	cfgfatal(loc,"rsa-private","we don't support encrypted keyfiles\n");
    }

    /* Read the public key */
    keyfile_get_int(loc,f); /* Not sure what this is */
    length=(keyfile_get_short(loc,f)+7)/8;
    if (length>RSA_MAX_MODBYTES) {
	cfgfatal(loc,"rsa-private","implausible length %ld for modulus\n",
		 length);
    }
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f) != 1) {
	cfgfatal_maybefile(f,loc,"rsa-private","error reading modulus\n");
    }
    mpz_init(&st->n);
    read_mpbin(&st->n,b,length);
    free(b);
    length=(keyfile_get_short(loc,f)+7)/8;
    if (length>RSA_MAX_MODBYTES) {
	cfgfatal(loc,"rsa-private","implausible length %ld for e\n",length);
    }
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f)!=1) {
	cfgfatal_maybefile(f,loc,"rsa-private","error reading e\n");
    }
    mpz_init(&e);
    read_mpbin(&e,b,length);
    free(b);
    
    length=keyfile_get_int(loc,f);
    if (length>1024) {
	cfgfatal(loc,"rsa-private","implausibly long (%ld) key comment\n",
		 length);
    }
    c=safe_malloc(length+1,"rsapriv_apply");
    if (fread(c,length,1,f)!=1) {
	cfgfatal_maybefile(f,loc,"rsa-private","error reading key comment\n");
    }
    c[length]=0;

    /* Check that the next two pairs of characters are identical - the
       keyfile is not encrypted, so they should be */

    if (keyfile_get_short(loc,f) != keyfile_get_short(loc,f)) {
	cfgfatal(loc,"rsa-private","corrupt keyfile\n");
    }

    /* Read d */
    length=(keyfile_get_short(loc,f)+7)/8;
    if (length>RSA_MAX_MODBYTES) {
	cfgfatal(loc,"rsa-private","implausibly long (%ld) decryption key\n",
		 length);
    }
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f)!=1) {
	cfgfatal_maybefile(f,loc,"rsa-private",
			   "error reading decryption key\n");
    }
    mpz_init(&d);
    read_mpbin(&d,b,length);
    free(b);
    /* Read iqmp (inverse of q mod p) */
    length=(keyfile_get_short(loc,f)+7)/8;
    if (length>RSA_MAX_MODBYTES) {
	cfgfatal(loc,"rsa-private","implausibly long (%ld)"
		 " iqmp auxiliary value\n", length);
    }
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f)!=1) {
	cfgfatal_maybefile(f,loc,"rsa-private",
			   "error reading decryption key\n");
    }
    mpz_init(&iqmp);
    read_mpbin(&iqmp,b,length);
    free(b);
    /* Read q (the smaller of the two primes) */
    length=(keyfile_get_short(loc,f)+7)/8;
    if (length>RSA_MAX_MODBYTES) {
	cfgfatal(loc,"rsa-private","implausibly long (%ld) q value\n",
		 length);
    }
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f)!=1) {
	cfgfatal_maybefile(f,loc,"rsa-private",
			   "error reading q value\n");
    }
    mpz_init(&st->q);
    read_mpbin(&st->q,b,length);
    free(b);
    /* Read p (the larger of the two primes) */
    length=(keyfile_get_short(loc,f)+7)/8;
    if (length>RSA_MAX_MODBYTES) {
	cfgfatal(loc,"rsa-private","implausibly long (%ld) p value\n",
		 length);
    }
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f)!=1) {
	cfgfatal_maybefile(f,loc,"rsa-private",
			   "error reading p value\n");
    }
    mpz_init(&st->p);
    read_mpbin(&st->p,b,length);
    free(b);
    
    if (fclose(f)!=0) {
	fatal_perror("rsa-private (%s:%d): fclose",loc.file,loc.line);
    }

    /*
     * Now verify the validity of the key, and set up the auxiliary
     * values for fast CRT signing.
     */
    valid=False;
    i=list_elem(args,1);
    mpz_init(&tmp);
    mpz_init(&tmp2);
    mpz_init(&tmp3);
    if (i && i->type==t_bool && i->data.bool==False) {
	Message(M_INFO,"rsa-private (%s:%d): skipping RSA key validity "
		"check\n",loc.file,loc.line);
    } else {
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
    mpz_init(&st->dp);
    mpz_init(&st->dq);
    mpz_init(&st->w);
    mpz_sub_ui(&tmp, &st->p, 1);
    mpz_mod(&st->dp, &d, &tmp);
    mpz_sub_ui(&tmp, &st->q, 1);
    mpz_mod(&st->dq, &d, &tmp);
    mpz_mul(&st->w, &iqmp, &st->q);
    
done_checks:
    if (!valid) {
	cfgfatal(loc,"rsa-private","file \"%s\" does not contain a "
		 "valid RSA key!\n",filename);
    }
    mpz_clear(&tmp);
    mpz_clear(&tmp2);
    mpz_clear(&tmp3);

    free(c);
    mpz_clear(&e);
    mpz_clear(&d);
    mpz_clear(&iqmp);

assume_valid:
    return new_closure(&st->cl);
}

void rsa_module(dict_t *dict)
{
    add_closure(dict,"rsa-private",rsapriv_apply);
    add_closure(dict,"rsa-public",rsapub_apply);
}
