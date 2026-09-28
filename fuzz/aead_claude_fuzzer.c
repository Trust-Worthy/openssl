/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * Fuzz AES-256-GCM, AES-256-CCM and AES-256-GCM-SIV.
 *
 * The first input byte selects a mode:
 *
 *   even: round trip.  Fuzzer-chosen key, nonce, AAD, plaintext, split
 *         points and CCM tag and nonce lengths.  Calls follow the order
 *         used by test/evp_test.c.  Aborts if a correct decryption fails
 *         or returns the wrong plaintext, or if a modified tag, AAD or
 *         ciphertext is accepted.
 *
 *   odd:  call sequence (GCM and GCM-SIV).  The input is a list of EVP
 *         operations.  Aborts if an encryption in which every call
 *         succeeded gives a different ciphertext or tag than a single
 *         reference encryption of the same AAD and plaintext.  Everything
 *         else relies on ASan and UBSan.
 *
 * Set AEAD_FUZZ_STRICT=1 to abort when a call sequence that should be
 * valid fails, and to print how often each check ran on exit.  Use it to
 * confirm the harness reaches its checks.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "fuzzer.h"

#define KEY_LEN     32
#define MAX_IV_LEN  13
#define MAX_TAG_LEN 16
#define RT_HDR      7
#define SEQ_MAX     1024
#define SEQ_BUF     (SEQ_MAX + 2 * EVP_MAX_BLOCK_LENGTH)

enum alg { ALG_GCM, ALG_CCM, ALG_SIV, ALG_COUNT };

static const char *const alg_names[ALG_COUNT] = {
    "AES-256-GCM", "AES-256-CCM", "AES-256-GCM-SIV"
};

typedef struct {
    enum alg alg;
    EVP_CIPHER *cipher;
    size_t ivlen;
    size_t taglen;
} AEAD_PARAMS;

static EVP_CIPHER *ciphers[ALG_COUNT];
static int strict;
static unsigned long rt_checks[ALG_COUNT];
static unsigned long seq_checks[ALG_COUNT];

static unsigned char seq_key[KEY_LEN];
static unsigned char seq_nonce[MAX_IV_LEN];
static unsigned char seq_tag[MAX_TAG_LEN];
static unsigned char aad_pattern[SEQ_MAX];
static unsigned char body_pattern[SEQ_MAX];

static void print_stats(void)
{
    int i;

    fprintf(stderr, "\n[aead] checks performed:\n");
    for (i = 0; i < ALG_COUNT; i++)
        fprintf(stderr, "  %-16s round trip: %lu  sequence: %lu\n",
                alg_names[i], rt_checks[i], seq_checks[i]);
}

static void oracle_failure(const char *what, enum alg alg)
{
    fprintf(stderr, "\n[aead] ORACLE FAILURE (%s): %s\n", alg_names[alg], what);
    abort();
}

static void harness_failure(const char *what, enum alg alg)
{
    fprintf(stderr, "\n[aead] HARNESS CHECK FAILED (%s): %s\n",
            alg_names[alg], what);
    abort();
}

int FuzzerInitialize(int *argc, char ***argv)
{
    const char *s;
    uint32_t x = 0x9e3779b9u;
    size_t i;

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_clear_error();

    for (i = 0; i < ALG_COUNT; i++)
        ciphers[i] = EVP_CIPHER_fetch(NULL, alg_names[i], NULL);

    memset(seq_key, 0xAA, sizeof(seq_key));
    memset(seq_nonce, 0xBB, sizeof(seq_nonce));
    memset(seq_tag, 0xCC, sizeof(seq_tag));

    /* Non-repeating bytes, so reordered or dropped input changes the result */
    for (i = 0; i < SEQ_MAX; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        aad_pattern[i] = (unsigned char)x;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        body_pattern[i] = (unsigned char)x;
    }

    s = getenv("AEAD_FUZZ_STRICT");
    strict = s != NULL && *s != '\0' && *s != '0';
    if (strict)
        atexit(print_stats);
    return 1;
}

static int get_params(enum alg alg, size_t ccm_ivlen, size_t ccm_taglen,
                      AEAD_PARAMS *p)
{
    p->alg = alg;
    p->cipher = ciphers[alg];
    p->ivlen = alg == ALG_CCM ? ccm_ivlen : 12;
    p->taglen = alg == ALG_CCM ? ccm_taglen : 16;
    return p->cipher != NULL;
}

/*
 * Feed |in| to Update() in |nchunks| pieces.  |out| == NULL feeds AAD.
 * Zero-length pieces are skipped, so no zero-length call is ever made.
 */
static int chunked_update(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          int *outl_total, const unsigned char *in,
                          size_t inl, unsigned int nchunks)
{
    size_t done = 0;
    unsigned int i;

    if (nchunks == 0)
        nchunks = 1;

    for (i = 0; i < nchunks; i++) {
        size_t take = (inl - done) / (nchunks - i);
        int outl = 0;

        if (take == 0)
            continue;
        if (!EVP_CipherUpdate(ctx, out != NULL ? out + *outl_total : NULL,
                              &outl, in + done, (int)take))
            return 0;
        *outl_total += outl;
        done += take;
    }
    assert(done == inl);
    return 1;
}

/*
 * CCM takes AAD and payload in one call each, after declaring the payload
 * length.  GCM-SIV takes the payload in one call.  GCM takes both in any
 * number of calls.
 */
static void limit_chunks(enum alg alg, unsigned int *aad_chunks,
                         unsigned int *data_chunks)
{
    if (alg == ALG_CCM)
        *aad_chunks = 1;
    if (alg == ALG_CCM || alg == ALG_SIV)
        *data_chunks = 1;
}

static int do_encrypt(const AEAD_PARAMS *p, const unsigned char *key,
                      const unsigned char *nonce,
                      const unsigned char *aad, size_t aad_len,
                      unsigned int aad_chunks,
                      const unsigned char *pt, size_t pt_len,
                      unsigned int pt_chunks,
                      unsigned char *ct, int *ct_len, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    OSSL_PARAM params[2];
    int unused = 0, tmplen = 0, ok = 0;

    *ct_len = 0;
    if (ctx == NULL)
        return 0;
    limit_chunks(p->alg, &aad_chunks, &pt_chunks);

    if (!EVP_EncryptInit_ex2(ctx, p->cipher, NULL, NULL, NULL))
        goto end;
    if (p->alg == ALG_CCM
        && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                (int)p->ivlen, NULL) <= 0
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                   (int)p->taglen, NULL) <= 0))
        goto end;
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, nonce, -1))
        goto end;
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (p->alg == ALG_CCM
        && !EVP_EncryptUpdate(ctx, NULL, &unused, NULL, (int)pt_len))
        goto end;
    if (!chunked_update(ctx, NULL, &unused, aad, aad_len, aad_chunks))
        goto end;
    if (!chunked_update(ctx, ct, ct_len, pt, pt_len, pt_chunks))
        goto end;
    if (!EVP_EncryptFinal_ex(ctx, ct + *ct_len, &tmplen))
        goto end;
    *ct_len += tmplen;

    /* CCM only returns a tag of exactly the length it was set up with */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  tag, p->taglen);
    params[1] = OSSL_PARAM_construct_end();
    ok = EVP_CIPHER_CTX_get_params(ctx, params);

 end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/*
 * Returns 1 if accepted, 0 if setup failed, -1 if rejected.
 * The expected tag is set before the key and nonce, as test/evp_test.c
 * does.  GCM-SIV requires that order.
 */
static int do_decrypt(const AEAD_PARAMS *p, const unsigned char *key,
                      const unsigned char *nonce, const unsigned char *tag,
                      const unsigned char *aad, size_t aad_len,
                      unsigned int aad_chunks,
                      const unsigned char *ct, size_t ct_len,
                      unsigned int ct_chunks,
                      unsigned char *out, int *out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int unused = 0, tmplen = 0, rv = 0;

    *out_len = 0;
    if (ctx == NULL)
        return 0;
    limit_chunks(p->alg, &aad_chunks, &ct_chunks);

    if (!EVP_DecryptInit_ex2(ctx, p->cipher, NULL, NULL, NULL))
        goto end;
    if (p->alg == ALG_CCM
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                               (int)p->ivlen, NULL) <= 0)
        goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)p->taglen,
                            (void *)tag) <= 0)
        goto end;
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, nonce, -1))
        goto end;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (p->alg == ALG_CCM
        && !EVP_DecryptUpdate(ctx, NULL, &unused, NULL, (int)ct_len))
        goto end;

    /*
     * Setup is done.  Any failure from here is a rejection: CCM checks the
     * tag inside the payload Update, GCM and GCM-SIV in Final.  Final is
     * called for every mode, since CCM checks an empty payload there.
     */
    rv = -1;
    if (!chunked_update(ctx, NULL, &unused, aad, aad_len, aad_chunks))
        goto end;
    if (!chunked_update(ctx, out, out_len, ct, ct_len, ct_chunks))
        goto end;
    if (EVP_DecryptFinal_ex(ctx, out + *out_len, &tmplen) <= 0)
        goto end;
    *out_len += tmplen;
    rv = 1;

 end:
    EVP_CIPHER_CTX_free(ctx);
    return rv;
}

static void run_round_trip(const uint8_t *buf, size_t len)
{
    AEAD_PARAMS p;
    const unsigned char *key, *nonce, *aad, *pt;
    unsigned char tag[MAX_TAG_LEN], bad_tag[MAX_TAG_LEN], bit;
    unsigned char *ct = NULL, *out = NULL, *scratch = NULL;
    unsigned int enc_chunks, dec_chunks;
    size_t aad_len, pt_len, idx;
    int ct_len = 0, out_len = 0, rv;
    enum alg alg;

    if (len < RT_HDR + KEY_LEN + MAX_IV_LEN)
        return;

    alg = (enum alg)(buf[0] % ALG_COUNT);
    enc_chunks = buf[1] % 8 + 1;
    dec_chunks = buf[2] % 8 + 1;
    aad_len = buf[3];
    /* CCM tag length 4..16 (even), nonce length 7..13 */
    if (!get_params(alg, 7 + buf[5] % 7, 4 + 2 * (buf[4] % 7), &p))
        return;
    idx = buf[6];
    bit = (unsigned char)(1u << (buf[6] >> 5));
    buf += RT_HDR;
    len -= RT_HDR;

    key = buf;
    nonce = buf + KEY_LEN;
    buf += KEY_LEN + MAX_IV_LEN;
    len -= KEY_LEN + MAX_IV_LEN;

    aad_len %= len + 1;
    aad = buf;
    pt = buf + aad_len;
    pt_len = len - aad_len;

    ct = OPENSSL_malloc(pt_len + 2 * EVP_MAX_BLOCK_LENGTH);
    out = OPENSSL_malloc(pt_len + 2 * EVP_MAX_BLOCK_LENGTH);
    scratch = OPENSSL_malloc(aad_len + pt_len + 2 * EVP_MAX_BLOCK_LENGTH);
    if (ct == NULL || out == NULL || scratch == NULL)
        goto end;

    if (!do_encrypt(&p, key, nonce, aad, aad_len, enc_chunks,
                    pt, pt_len, enc_chunks, ct, &ct_len, tag)) {
        if (strict)
            harness_failure("valid encryption failed", alg);
        goto end;
    }

    rv = do_decrypt(&p, key, nonce, tag, aad, aad_len, dec_chunks,
                    ct, (size_t)ct_len, dec_chunks, out, &out_len);
    if (rv == 0) {
        if (strict)
            harness_failure("valid decryption setup failed", alg);
        goto end;
    }
    if (rv < 0)
        oracle_failure("correct tag rejected", alg);
    if ((size_t)out_len != pt_len
        || (pt_len > 0 && memcmp(out, pt, pt_len) != 0))
        oracle_failure("decryption did not return the plaintext", alg);
    rt_checks[alg]++;

    /* A modified tag is rejected whatever the tag length */
    memcpy(bad_tag, tag, p.taglen);
    bad_tag[idx % p.taglen] ^= bit;
    if (do_decrypt(&p, key, nonce, bad_tag, aad, aad_len, dec_chunks,
                   ct, (size_t)ct_len, dec_chunks, out, &out_len) > 0)
        oracle_failure("modified tag accepted", alg);

    /*
     * A modified AAD or ciphertext is accepted by chance with probability
     * 2^-(8 * taglen).  Skip 4-byte tags, where that is reachable.
     */
    if (p.taglen < 6)
        goto end;

    if (aad_len > 0) {
        memcpy(scratch, aad, aad_len);
        scratch[idx % aad_len] ^= bit;
        if (do_decrypt(&p, key, nonce, tag, scratch, aad_len, dec_chunks,
                       ct, (size_t)ct_len, dec_chunks, out, &out_len) > 0)
            oracle_failure("modified AAD accepted", alg);
    }
    if (ct_len > 0) {
        memcpy(scratch, ct, (size_t)ct_len);
        scratch[idx % (size_t)ct_len] ^= bit;
        if (do_decrypt(&p, key, nonce, tag, aad, aad_len, dec_chunks,
                       scratch, (size_t)ct_len, dec_chunks, out, &out_len) > 0)
            oracle_failure("modified ciphertext accepted", alg);
    }

 end:
    OPENSSL_free(ct);
    OPENSSL_free(out);
    OPENSSL_free(scratch);
}

/* ---- Call-sequence mode ---- */

enum {
    OP_INIT_ENC, OP_INIT_DEC, OP_UPDATE_AAD, OP_UPDATE_BODY, OP_FINAL,
    OP_SET_TAG, OP_GET_TAG, OP_SET_TAG_LEN, OP_COPY_CTX, OP_ONESHOT,
    OP_RESET, OP_COUNT
};

typedef enum { ST_NEW, ST_ACTIVE, ST_DONE, ST_ERROR } SEQ_STATE;

/* What the reference encryption must reproduce */
typedef struct {
    size_t aad_start;   /* AAD before this offset was discarded */
    size_t aad_end;     /* AAD supplied so far */
    size_t body_len;    /* plaintext supplied so far */
    int body_seen;
    int unmodelled;     /* a call the reference does not reproduce succeeded */
} SEQ_MODEL;

static size_t clamp(size_t want, size_t room)
{
    return want < room ? want : room;
}

static void seq_check(const AEAD_PARAMS *p, EVP_CIPHER_CTX *ctx,
                      const SEQ_MODEL *m, const unsigned char *ct,
                      size_t ct_len)
{
    unsigned char tag[MAX_TAG_LEN], ref_tag[MAX_TAG_LEN];
    unsigned char ref_ct[SEQ_BUF];
    int ref_len = 0;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)p->taglen,
                            tag) <= 0) {
        if (strict)
            harness_failure("no tag after a successful Final", p->alg);
        return;
    }
    if (!do_encrypt(p, seq_key, seq_nonce, aad_pattern + m->aad_start,
                    m->aad_end - m->aad_start, 1,
                    body_pattern, m->body_len, 1, ref_ct, &ref_len, ref_tag)) {
        if (strict)
            harness_failure("reference encryption failed", p->alg);
        return;
    }
    if ((size_t)ref_len != ct_len || memcmp(ref_ct, ct, ct_len) != 0)
        oracle_failure("call sequence changed the ciphertext", p->alg);
    if (memcmp(ref_tag, tag, p->taglen) != 0)
        oracle_failure("call sequence changed the tag", p->alg);
    seq_checks[p->alg]++;
}

static void run_sequence(const uint8_t *buf, size_t len)
{
    AEAD_PARAMS p;
    EVP_CIPHER_CTX *ctx, *clone = NULL;
    SEQ_MODEL m;
    SEQ_STATE st = ST_NEW;
    unsigned char out[SEQ_BUF], scratch[SEQ_BUF];
    size_t out_len = 0, amt;
    int enc = -1, outl, ok, sticky_unmodelled = 0;

    /* CCM is left out: it takes AAD and payload in one call each */
    if (len < 1 || !get_params((buf[0] & 1) ? ALG_SIV : ALG_GCM, 0, 0, &p))
        return;
    buf++;
    len--;

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        return;
    memset(&m, 0, sizeof(m));

    for (; len >= 2; buf += 2, len -= 2) {
        int op = buf[0] % OP_COUNT;
        size_t want = (size_t)buf[1] * 4;

        outl = 0;
        if (st == ST_ERROR && op != OP_INIT_ENC && op != OP_INIT_DEC
            && op != OP_RESET)
            continue;

        switch (op) {
        case OP_INIT_ENC:
        case OP_INIT_DEC:
            enc = op == OP_INIT_ENC;
            memset(&m, 0, sizeof(m));
            out_len = 0;
            if (enc)
                ok = EVP_EncryptInit_ex2(ctx, p.cipher, seq_key, seq_nonce,
                                         NULL);
            else
                ok = EVP_DecryptInit_ex2(ctx, p.cipher, NULL, NULL, NULL)
                     && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                            (int)p.taglen, seq_tag) > 0
                     && EVP_CipherInit_ex(ctx, NULL, NULL, seq_key, seq_nonce,
                                          -1);
            st = ok ? ST_ACTIVE : ST_ERROR;
            break;

        case OP_UPDATE_AAD:
            if (st == ST_DONE) {
                /* After Final: result ignored, must not crash */
                (void)EVP_CipherUpdate(ctx, NULL, &outl, aad_pattern,
                                       (int)clamp(want, 64));
                break;
            }
            if (st != ST_ACTIVE)
                break;
            amt = clamp(want, SEQ_MAX - m.aad_end);
            if (!EVP_CipherUpdate(ctx, NULL, &outl, aad_pattern + m.aad_end,
                                  (int)amt)) {
                st = ST_ERROR;
                break;
            }
            /* GCM-SIV discards earlier AAD on a zero-length AAD update */
            if (p.alg == ALG_SIV && amt == 0)
                m.aad_start = m.aad_end;
            m.aad_end += amt;
            if (m.body_seen)
                m.unmodelled = 1;
            break;

        case OP_UPDATE_BODY:
            if (st == ST_DONE) {
                (void)EVP_CipherUpdate(ctx, scratch, &outl, body_pattern,
                                       (int)clamp(want, 64));
                break;
            }
            if (st != ST_ACTIVE)
                break;
            amt = clamp(want, SEQ_MAX - m.body_len);
            if (!EVP_CipherUpdate(ctx, out + out_len, &outl,
                                  body_pattern + m.body_len, (int)amt)) {
                st = ST_ERROR;
                break;
            }
            if (outl < 0 || (size_t)outl > amt) {
                m.unmodelled = 1;
                outl = 0;
            }
            out_len += (size_t)outl;
            m.body_len += amt;
            m.body_seen = 1;
            break;

        case OP_FINAL:
            if (st == ST_DONE) {
                (void)EVP_CipherFinal_ex(ctx, scratch, &outl);
                break;
            }
            if (st != ST_ACTIVE)
                break;
            if (enc) {
                if (!EVP_EncryptFinal_ex(ctx, out + out_len, &outl)) {
                    st = ST_ERROR;
                    break;
                }
                if (outl > 0 && (size_t)outl <= SEQ_BUF - out_len)
                    out_len += (size_t)outl;
                st = ST_DONE;
                if (!m.unmodelled && !sticky_unmodelled)
                    seq_check(&p, ctx, &m, out, out_len);
            } else {
                /* The expected tag is a fixed pattern, so failure is normal */
                st = EVP_DecryptFinal_ex(ctx, out + out_len, &outl) > 0
                     ? ST_DONE : ST_ERROR;
            }
            break;

        case OP_SET_TAG:
            if (st == ST_ACTIVE && !enc)
                (void)EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                          (int)p.taglen, seq_tag);
            break;

        case OP_GET_TAG:
            if (st == ST_DONE && enc)
                (void)EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                                          (int)p.taglen, scratch);
            break;

        case OP_SET_TAG_LEN:
            /* May outlive a re-init, so it disables checks until reset */
            if (st == ST_ACTIVE
                && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                       4 + (int)(want % 13), NULL) > 0)
                sticky_unmodelled = 1;
            break;

        case OP_COPY_CTX:
            /*
             * Freeing the previous copy and continuing on |ctx| lets ASan
             * catch shared state.  Using the copy must not change |ctx|,
             * which seq_check() verifies.
             */
            EVP_CIPHER_CTX_free(clone);
            clone = NULL;
            if (st != ST_ACTIVE && st != ST_DONE)
                break;
            if ((clone = EVP_CIPHER_CTX_new()) == NULL)
                break;
            if (!EVP_CIPHER_CTX_copy(clone, ctx)) {
                EVP_CIPHER_CTX_free(clone);
                clone = NULL;
                break;
            }
            if (st == ST_ACTIVE)
                (void)EVP_CipherUpdate(clone, scratch, &outl, body_pattern,
                                       (int)clamp(want, SEQ_MAX));
            break;

        case OP_ONESHOT:
            if (st != ST_ACTIVE)
                break;
            (void)EVP_Cipher(ctx, scratch, body_pattern,
                             (unsigned int)clamp(want, SEQ_MAX));
            m.unmodelled = 1;
            break;

        case OP_RESET:
            (void)EVP_CIPHER_CTX_reset(ctx);
            st = ST_NEW;
            enc = -1;
            out_len = 0;
            sticky_unmodelled = 0;
            memset(&m, 0, sizeof(m));
            break;
        }
        ERR_clear_error();
    }

    EVP_CIPHER_CTX_free(clone);
    EVP_CIPHER_CTX_free(ctx);
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    if (len < 1)
        return 0;
    if (buf[0] & 1)
        run_sequence(buf + 1, len - 1);
    else
        run_round_trip(buf + 1, len - 1);
    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
    size_t i;

    for (i = 0; i < ALG_COUNT; i++)
        EVP_CIPHER_free(ciphers[i]);
}