#include <stdio.h>
#include <gmp.h>
#include "secnet.h"
#include "util.h"

#define AUTHFILE_ID_STRING "SSH PRIVATE KEY FILE FORMAT 1.1\n"

struct rsapriv {
    closure_t cl;
    struct rsaprivkey_if ops;
    struct cloc loc;
    MP_INT d;
    MP_INT n;
};
struct rsapub {
    closure_t cl;
    struct rsapubkey_if ops;
    struct cloc loc;
    MP_INT e;
    MP_INT n;
};
/* Sign data. NB data must be smaller than modulus */

static char *hexchars="0123456789abcdef";

static string_t rsa_sign(void *sst, uint8_t *data, uint32_t datalen)
{
    struct rsapriv *st=sst;
    MP_INT a, b;
    char buff[2048];
    int msize, i;
    string_t signature;

    mpz_init(&a);
    mpz_init(&b);

    msize=mpz_sizeinbase(&st->n, 16);

    if (datalen*2+4>=msize) {
	fatal("rsa_sign: message too big");
    }

    strcpy(buff,"0001");

    for (i=0; i<datalen; i++) {
	buff[4+i*2]=hexchars[(data[i]&0xf0)>>4];
	buff[5+i*2]=hexchars[data[i]&0xf];
    }
    buff[4+datalen*2]=0;
    
    for (i=datalen*2+4; i<msize; i++)
	buff[i]='f';

    buff[msize]=0;

    mpz_set_str(&a, buff, 16);

    mpz_powm(&b, &a, &st->d, &st->n);

    signature=write_mpstring(&b);

    mpz_clear(&b);
    mpz_clear(&a);
    return signature;
}

static bool_t rsa_sig_check(void *sst, uint8_t *data, uint32_t datalen,
			    string_t signature)
{
    struct rsapub *st=sst;
    MP_INT a, b, c;
    char buff[2048];
    int msize, i;
    bool_t ok;

    mpz_init(&a);
    mpz_init(&b);
    mpz_init(&c);

    msize=mpz_sizeinbase(&st->n, 16);

    strcpy(buff,"0001");

    for (i=0; i<datalen; i++) {
	buff[4+i*2]=hexchars[(data[i]&0xf0)>>4];
	buff[5+i*2]=hexchars[data[i]&0xf];
    }
    buff[4+datalen*2]=0;

    for (i=datalen*2+4; i<msize; i++)
	buff[i]='f';

    buff[msize]=0;

    mpz_set_str(&a, buff, 16);

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
	    cfgfatal(i->loc,"rsa-public","first argument must be a string");
	}
	e=i->data.string;
	if (mpz_init_set_str(&st->e,e,10)!=0) {
	    cfgfatal(i->loc,"rsa-public","encryption key \"%s\" is not a "
		     "decimal number string\n",e);
	}
    } else {
	cfgfatal(loc,"rsa-public","you must provide an encryption key\n");
    }
    
    i=list_elem(args,1);
    if (i) {
	if (i->type!=t_string) {
	    cfgfatal(i->loc,"rsa-public","second argument must be a string");
	}
	n=i->data.string;
	if (mpz_init_set_str(&st->n,n,10)!=0) {
	    cfgfatal(i->loc,"rsa-public","modulus \"%s\" is not a decimal "
		     "number string\n",n);
	}
    } else {
	cfgfatal(loc,"rsa-public","you must provide a modulus\n");
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
    string_t filename;
    item_t *i;
    long length;
    uint8_t *b, *c;
    int cipher_type;
    MP_INT e,sig,plain,check;

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
	    cfgfatal(i->loc,"rsa-public","first argument must be a string");
	}
	filename=i->data.string;
    } else {
	filename=""; /* Make compiler happy */
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
    if (length>1024) {
	cfgfatal(loc,"rsa-private","implausible length %ld for modulus\n",
		 length);
    }
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f) != 1) {
	cfgfatal_maybefile(f,loc,"rsa-private","error reading modulus");
    }
    mpz_init(&st->n);
    read_mpbin(&st->n,b,length);
    free(b);
    length=(keyfile_get_short(loc,f)+7)/8;
    if (length>1024) {
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
    if (length>1024) {
	cfgfatal(loc,"rsa-private","implausibly long (%ld) decryption key\n",
		 length);
    }
    b=safe_malloc(length,"rsapriv_apply");
    if (fread(b,length,1,f)!=1) {
	cfgfatal_maybefile(f,loc,"rsa-private",
			   "error reading decryption key\n");
    }
    mpz_init(&st->d);
    read_mpbin(&st->d,b,length);
    free(b);
    
    if (fclose(f)!=0) {
	fatal_perror("rsa-private (%s:%d): fclose",loc.file,loc.line);
    }

    /* Now do trial signature/check to make sure it's a real keypair:
       sign the comment string! */
    i=list_elem(args,1);
    if (i && i->type==t_bool && i->data.bool==False) {
	Message(M_INFO,"rsa-private (%s:%d): skipping RSA key validity "
		"check\n",loc.file,loc.line);
    } else {
	mpz_init(&sig);
	mpz_init(&plain);
	mpz_init(&check);
	read_mpbin(&plain,c,strlen(c));
	mpz_powm(&sig, &plain, &st->d, &st->n);
	mpz_powm(&check, &sig, &e, &st->n);
	if (mpz_cmp(&plain,&check)!=0) {
	    cfgfatal(loc,"rsa-private","file \"%s\" does not contain a "
		     "valid RSA key!\n",filename);
	}
	mpz_clear(&sig);
	mpz_clear(&plain);
	mpz_clear(&check);
    }

    free(c);
    mpz_clear(&e);

assume_valid:
    return new_closure(&st->cl);
}

init_module rsa_module;
void rsa_module(dict_t *dict)
{
    add_closure(dict,"rsa-private",rsapriv_apply);
    add_closure(dict,"rsa-public",rsapub_apply);
}
