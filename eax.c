/*
 * eax.c: implementation of the EAX authenticated encryption block cipher mode
 */
/*
 * Copyright 2013 Ian Jackson
 * Copyright 2013 Mark Wooding
 *
 * This file is Free Software.  It was originally written for secnet.
 *
 * You may redistribute it and/or modify it under the terms of the GNU
 * General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * This file is designed to be #included into another .c file which
 * sets up the environment.  It will declare or define three
 * functions, eax_setup, eax_encrypt and eax_decrypt.
 *
 * Manifest constants which are expected to be defined:
 *
 *  INFO       One or more formal parameter definitions.
 *             Used in all relevant function declarations.  Typically
 *             the application will use this for its context pointer,
 *             key schedule structure, etc.
 *
 *  I          Corresponding actual parameters for chaining onto
 *             sub-functions declared to take INFO parameters
 *
 *  EAX_ENTRYPOINT_DECL
 *             Declarator decoration for the three entry points.
 *             Typically either "static" or the empty string;
 *
 *  EAX_DECLARATIONS_ONLY
 *             Tested with #ifdef, so should be #defined to 1, or left
 *             undefined.  If defined, #including eax.c will produces
 *             only the function prototypes for the three entrypoints.
 *             Otherwise it will produce the implementation.
 *
 *  BLOCK_SIZE
 *             Constant expresion of integer type.
 *
 *  void BLOCK_ENCRYPT(uint8_t dst[n], const uint8_t src[n]);
 *
 *             Function to encrypt with the selected key.  The block
 *             cipher's key schedule (ie, the key) to be used is
 *             implicit; uses of BLOCK_ENCRYPT always occur in a
 *             context where the parameters defined by INFO are
 *             available.
 *
 *             So in a real application which wants to use more than
 *             one key at a time, BLOCK_ENCRYPT must be a macro which
 *             accesses the block cipher's key schedule via one of the
 *             INFO parameters.
 *
 *             BLOCK_ENCRYPT must tolerate dst==src.
 *
 *             EAX does not need to use the block cipher's decryption
 *             function.
 *
 *  uint8_t INFO_B[n], INFO_P[n];
 *
 *             Buffers used by the algorithm; they are written by
 *             eax_setup and used by eax_encrypt and eax_decrypt.
 *
 *             That is, effectively they are the part of the key
 *             schedule specific to EAX.
 *
 *             An application which wants to use more than one key at
 *             a time must define these as macros which refer to
 *             key-specific variables via one of the INFO parameters.
 *
 *  int consttime_memeq(const void *s1, const void *s2, size_t n);
 *
 *             Like !memcmp(s1,s2,n) but takes the same amount of time
 *             no matter where the discrepancy is.  Result must be
 *             a canonicalised boolean.
 *
 * The entrypoints which are then defined are:
 *
 *  void eax_setup(INFO)
 *
 *      Does the EAX-specific part of the key setup.  The block
 *      cipher key schedule must already have been done, as
 *      eax_setup uses BLOCK_ENCRYPT.
 *
 *  void eax_encrypt(INFO, const uint8_t nonce[nonce_len], size_t nonce_len,
 *                         const uint8_t h[h_len], size_t h_len,
 *                         const uint8_t m[m_len], size_t m_len,
 *                         uint8_t tau,
 *                         uint8_t ct[m_len+tau])
 *
 *      Does a single EAX authenticated encryption, providing
 *      confidentiality and integrity to the message m[0..m_len-1].
 *
 *      The output message is longer than m by tau bytes and is stored
 *      in the array ct which must be big enough.
 *
 *      nonce must never be repeated with the same key or the security
 *      of the system is destroyed, but it does not need to be secret.
 *      It is OK to transmit the nonce with the message along with the
 *      ciphertext and have the receiver recover it.
 *
 *      h is the "header" - it is some extra data which should be
 *      covered by the authentication, but not the encryption.  The
 *      output message does not contain a representation of h: it is
 *      expected to be transmitted separately (perhaps even in a
 *      different format).  (If h_len==0, h may be a NULL pointer.)
 *
 *      tau is the tag length - that is, the length of the message
 *      authentication code.  It should be chosen for the right
 *      tradeoff between message expansion and security (resistence to
 *      forgery).  It must be no longer than the block cipher block
 *      size.
 *
 *      For any particular key.  the tag length should be fixed.  (The
 *      tag length should NOT be encoded into the packet along with
 *      the ciphertext and extracted by the receiver!  Rather, the
 *      receiver must know what tag length to expect.)
 *
 *      It is permissible for ct==m, or for the arrays to be disjoint.
 *      They must not overlap more subtly.
 *
 *  _Bool eax_decrypt(INFO, const uint8_t nonce[nonce_len], size_t nonce_len,
 *                          const uint8_t h[h_len], size_t h_len,
 *                          const uint8_t ct[ct_len], size_t ct_len,
 *                          uint8_t tau,
 *                          uint8_t m[ct_len-tau])
 *
 *      Does a single EAX authenticated decryption.
 *
 *      On successful return, the plaintext message is written to m
 *      and eax_decrypt returns true.  The length of the plaintext
 *      message is always ct_len-tau.
 *
 *      If the message did not decrypt correctly, returns false.
 *      (There is no further indication of the nature of the error.)
 *      In this case the buffer m may contain arbitrary contents which
 *      should not be revealed to attackers.
 *
 *      nonce, h, tau are as above.
 *
 *      It is permissible to call eax_decrypt with an input message
 *      which is too short (i.e. shorter than tau) (notwithstanding
 *      the notation m[ct_len-tau] in the faux prototype above).
 *      In this case it will return false without touching m.
 *
 *      As with eax_decrypt, ct==m is permissible.
 */

/***** IMPLEMENTATION *****/

/*
 * We use the notation from the EAX paper, mostly.
 * (We write xscr for "x in fancy mathsy curly script".)
 *
 * See:
 *  Mihir Bellare, Phillip Rogaway, and David Wagner
 *
 *  _The EAX Mode of Operation
 *   (A Two-Pass Authenticated Encryption Scheme
 *   Optimized for Simplicity and Efficiency)_
 *
 * Preliminary version in:
 *   Fast Software Encryption (FSE) 2004. Lecture Notes in Computer Science,
 *   vol. ??, pp. ??--??.
 *
 * Full version at:
 *  http://www.cs.ucdavis.edu/~rogaway/papers/eax.html
 */
/*
 * In general, all functions tolerate their destination arrays being
 * the same pointer to their source arrays, or totally distinct.
 * (Just like BLOCK_ENCRYPT and the public eax entrypoints.)
 * They must not overlap in more subtle ways.
 */

#define n ((size_t)BLOCK_SIZE)

#ifndef EAX_DECLARATIONS_ONLY

static void xor_block(uint8_t *dst, const uint8_t *a, const uint8_t *b,
                      size_t l)
    /* simple block xor */
{
    while (l--)
        *dst++ = *a++ ^ *b++;
}

static void increment(uint8_t *value)
    /* value is a single block; incremented (BE) mod 256^n */
{
    uint8_t *p;
    for (p=value+n; p>value; )
        if ((*--p)++) break;
}

static void alg_ctr(INFO, uint8_t *c, const uint8_t *nscr,
                    const uint8_t *m, size_t m_len)
{
    uint8_t blocknonce[n], cipher[n];
    size_t in;

    memcpy(blocknonce, nscr, n);
    for (in=0; in<m_len; in+=n) {
        BLOCK_ENCRYPT(cipher,blocknonce);
        increment(blocknonce);
        size_t now = m_len-in < n ? m_len-in : n;
        xor_block(c+in, m+in, cipher, now);
    }
}

static void alg_omac_t_k(INFO, uint8_t *mac_out, uint8_t t,
                         const uint8_t *m, size_t m_len)
{
    /* Initial tweak. */
    memset(mac_out, 0, n-1);
    mac_out[n-1] = t;

    /* All of the whole blocks. */
    size_t in=0;
    for (; in+n <= m_len; in+=n) {
        BLOCK_ENCRYPT(mac_out, mac_out);
        xor_block(mac_out, mac_out, m+in, n);
    }

    /* The last partial block, if there is one. */
    assert(in <= m_len);
    size_t remain = m_len - in;
    if (!remain)
        xor_block(mac_out, mac_out, INFO_B, n);
    else {
        BLOCK_ENCRYPT(mac_out, mac_out);
        xor_block(mac_out, mac_out, m+in, remain);
        mac_out[remain] ^= 0x80;
        xor_block(mac_out, mac_out, INFO_P, n);
    }

    /* Final block-cipher application. */
    BLOCK_ENCRYPT(mac_out, mac_out);
}

/*
 * Constant-time multiply-by-x in F = GF(2^128), using the EAX representation
 * F = GF(2)[x]/(x^128 + x^7 + x^2 + x + 1).
 *
 * The input vector V consists of the input polynomial L = a_127 x^127 +
 * ... + a_1 x + a_0; specifically, the byte v[15 - i] contains a_{8i+7}
 * x^{8i+7} + ... + a_{8i} x^{8i}.  The output vector O will contain L x on
 * exit, using the same encoding.
 *
 * It is fine if O = V, or the two vectors are disjoint; Bad Things will
 * happen if they overlap in some more complicated way.
 */
static void consttime_curious_multiply(INFO, uint8_t *o, const uint8_t *v)
{
#define POLY 0x87u

  unsigned m = ~((v[0] >> 7) - 1u) & POLY;
  unsigned i, mm;

  for (i = n - 1; i < n; i--) {
    mm = (v[i] >> 7) & 1u;
    o[i] = (v[i] << 1) ^ m;
    m = mm;
  }

#undef POLY
}

#endif /* not EAX_DECLARATIONS_ONLY */

EAX_ENTRYPOINT_DECL
void eax_setup(INFO)
#ifndef EAX_DECLARATIONS_ONLY
{
    uint8_t work[n];
    memset(work,0,n);
    BLOCK_ENCRYPT(work,work);
    consttime_curious_multiply(I, INFO_B, work);
    consttime_curious_multiply(I, INFO_P, INFO_B);
}
#endif /* not EAX_DECLARATIONS_ONLY */
;

EAX_ENTRYPOINT_DECL
void eax_encrypt(INFO,
                 const uint8_t *nonce, size_t nonce_len,
                 const uint8_t *h, size_t h_len,
                 const uint8_t *m, size_t m_len, uint8_t tau, uint8_t *ct)
#ifndef EAX_DECLARATIONS_ONLY
{
    assert(tau <= n);
    uint8_t nscr[n], hscr[n], cscr[n];
    alg_omac_t_k(I, nscr, 0, nonce,nonce_len);
    alg_omac_t_k(I, hscr, 1, h,h_len);
    alg_ctr(I, ct, nscr, m, m_len);
    alg_omac_t_k(I, cscr, 2, ct, m_len);
    uint8_t *t = ct + m_len;
    xor_block(t, nscr, cscr, tau);
    xor_block(t, t, hscr, tau);
}
#endif /* not EAX_DECLARATIONS_ONLY */
;

EAX_ENTRYPOINT_DECL
_Bool eax_decrypt(INFO,
                  const uint8_t *nonce, size_t nonce_len,
                  const uint8_t *h, size_t h_len,
                  const uint8_t *ct, size_t ct_len, uint8_t tau, uint8_t *m)
#ifndef EAX_DECLARATIONS_ONLY
{
    assert(tau <= n);
    const uint8_t *t;
    uint8_t nscr[n], hscr[n], cscr[n], tprime[tau];
    if (ct_len < tau) return 0;
    size_t m_len = ct_len - tau;
    t = ct + m_len;
    alg_omac_t_k(I, nscr, 0, nonce,nonce_len);
    alg_omac_t_k(I, hscr, 1, h,h_len);
    alg_omac_t_k(I, cscr, 2, ct,m_len);
    xor_block(tprime, nscr, cscr, tau);
    xor_block(tprime, tprime, hscr, tau);
    if (!consttime_memeq(tprime, t, tau)) return 0;
    alg_ctr(I, m, nscr, ct, m_len);
    return 1;
}
#endif /* not EAX_DECLARATIONS_ONLY */
;

#undef n
