#include <stdio.h>
#include <gmp.h>
#include <limits.h>

#include "secnet.h"
#include "util.h"

struct dh {
    closure_t cl;
    struct dh_if ops;
    struct cloc loc;
    MP_INT p,g; /* prime modulus and generator */
};

static string_t dh_makepublic(void *sst, uint8_t *secret, uint32_t secretlen)
{
    struct dh *st=sst;
    string_t r;
    MP_INT a, b; /* a is secret key, b is public key */

    mpz_init(&a);
    mpz_init(&b);

    read_mpbin(&a, secret, secretlen);

    mpz_powm(&b, &st->g, &a, &st->p);

    r=write_mpstring(&b);

    mpz_clear(&a);
    mpz_clear(&b);
    return r;
}

static dh_makeshared_fn dh_makeshared;
static void dh_makeshared(void *sst, uint8_t *secret, uint32_t secretlen,
			  cstring_t rempublic, uint8_t *sharedsecret,
			  uint32_t buflen)
{
    struct dh *st=sst;
    MP_INT a, b, c;

    mpz_init(&a);
    mpz_init(&b);
    mpz_init(&c);

    read_mpbin(&a, secret, secretlen);
    mpz_set_str(&b, rempublic, 16);

    mpz_powm(&c, &b, &a, &st->p);

    write_mpbin(&c,sharedsecret,buflen);

    mpz_clear(&a);
    mpz_clear(&b);
    mpz_clear(&c);
}

static list_t *dh_apply(closure_t *self, struct cloc loc, dict_t *context,
			list_t *args)
{
    struct dh *st;
    string_t p,g;
    item_t *i;

    st=safe_malloc(sizeof(*st),"dh_apply");
    st->cl.description="dh";
    st->cl.type=CL_DH;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.makepublic=dh_makepublic;
    st->ops.makeshared=dh_makeshared;
    st->loc=loc;
    /* We have two string arguments: the first is the modulus, and the
       second is the generator. Both are in hex. */
    i=list_elem(args,0);
    if (i) {
	if (i->type!=t_string) {
	    cfgfatal(i->loc,"diffie-hellman","first argument must be a "
		     "string\n");
	}
	p=i->data.string;
	if (mpz_init_set_str(&st->p,p,16)!=0) {
	    cfgfatal(i->loc,"diffie-hellman","\"%s\" is not a hex number "
		     "string\n",p);
	}
    } else {
	cfgfatal(loc,"diffie-hellman","you must provide a prime modulus\n");
    }
    
    i=list_elem(args,1);
    if (i) {
	if (i->type!=t_string) {
	    cfgfatal(i->loc,"diffie-hellman","second argument must be a "
		     "string\n");
	}
	g=i->data.string;
	if (mpz_init_set_str(&st->g,g,16)!=0) {
	    cfgfatal(i->loc,"diffie-hellman","\"%s\" is not a hex number "
		     "string\n",g);
	}
    } else {
	cfgfatal(loc,"diffie-hellman","you must provide a generator\n");
    }

    i=list_elem(args,2);
    if (i && i->type==t_bool && i->data.bool==False) {
	Message(M_INFO,"diffie-hellman (%s:%d): skipping modulus "
		"primality check\n",loc.file,loc.line);
    } else {
	/* Test that the modulus is really prime */
	if (mpz_probab_prime_p(&st->p,5)==0) {
	    cfgfatal(loc,"diffie-hellman","modulus must be a prime\n");
	}
    }

    size_t sz=mpz_sizeinbase(&st->p,2)/8;
    if (sz>INT_MAX) {
	cfgfatal(loc,"diffie-hellman","modulus far too large\n");
    }
    if (mpz_cmp(&st->g,&st->p) >= 0) {
	cfgfatal(loc,"diffie-hellman","generator must be less than modulus\n");
    }

    st->ops.len=sz;

    return new_closure(&st->cl);
}

void dh_module(dict_t *dict)
{
    add_closure(dict,"diffie-hellman",dh_apply);
}
