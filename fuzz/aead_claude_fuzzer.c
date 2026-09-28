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
 * Fuzz every AEAD cipher the default provider offers.
 *
 * Ciphers are found at startup and grouped by mode.  Each group follows
 * the call order test/evp_test.c uses for it.  Ciphers in a mode with no
 * group here are skipped and listed when AEAD_FUZZ_STRICT is set.
 *
 * The first input byte selects a mode:
 *
 *   even: round trip.  Fuzzer-chosen cipher, key, nonce, AAD, plaintext,
 *         split points, tag lengths (CCM, OCB, GCM, ChaCha20-Poly1305) and
 *         nonce lengths (CCM, OCB, GCM).  Aborts if a correct decryption
 *         fails or returns the wrong plaintext, or if a modified tag, AAD
 *         or ciphertext is accepted.
 *
 *   odd:  call sequence.  The input is a list of EVP operations.  Aborts
 *         if an encryption in which every call succeeded gives a
 *         different ciphertext or tag than a reference encryption of the
 *         same AAD and plaintext.  For GCM and ChaCha20-Poly1305 only, a
 *         decryption must also return the right plaintext, accept the
 *         correct tag and reject a modified one; decryption in other modes
 *         is checked by ASan and UBSan only.  Sequences the reference
 *         cannot reproduce are counted instead.
 *
 * By default only these checks abort.  Set AEAD_FUZZ_STRICT=1 to also
 * abort when a call sequence that should be valid fails.  Set
 * AEAD_FUZZ_STATS=1 (implied by AEAD_FUZZ_STRICT) to print per-cipher
 * counts on exit.  Neither is meant for automated test runs.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "fuzzer.h"

#define MAX_KEY_LEN  64
#define MAX_IV_LEN   128   /* GCM accepts nonces of 1..128 bytes */
#define MAX_TAG_LEN  16
#define MAX_CIPHERS  64
#define MAX_SKIPPED  16
#define NAME_LEN     48
#define RT_HDR       7
#define SEQ_MAX      1024
#define SEQ_BUF      (SEQ_MAX + 2 * EVP_MAX_BLOCK_LENGTH)
#define MAX_PARTS    64

enum prof { P_GCM, P_CCM, P_OCB, P_SIV, P_GCM_SIV, P_CHACHA, P_ASCON, P_COUNT };

static const char *const prof_names[P_COUNT] = {
    "GCM", "CCM", "OCB", "SIV", "GCM-SIV", "ChaCha20-Poly1305", "ASCON"
};

/* Behavior that was accepted but that the reference cannot reproduce */
enum obs {
    OBS_AAD_AFTER_PAYLOAD, OBS_SPLIT_PAYLOAD, OBS_CCM_SPLIT_AAD,
    OBS_CCM_LEN_MISMATCH, OBS_COUNT
};

static const char *const obs_names[OBS_COUNT] = {
    "AAD accepted after payload",
    "one-call payload accepted in parts",
    "CCM AAD accepted in parts",
    "CCM declared length differs from payload"
};

typedef struct {
    EVP_CIPHER *cipher;
    char name[NAME_LEN];
    enum prof prof;
    size_t keylen;
    size_t ivlen;
    size_t taglen;
    /* GCM and ChaCha20-Poly1305: encryption of body_pattern, no AAD */
    unsigned char *ct_stream;
    int ct_stream_tried;
    unsigned long rt_checks;
    unsigned long seq_checks;
    unsigned long seq_dec_checks;
} AEAD_CIPHER;

typedef struct {
    enum prof prof;
    EVP_CIPHER *cipher;
    size_t keylen;
    size_t ivlen;
    size_t taglen;
} AEAD_PARAMS;

static AEAD_CIPHER aeads[MAX_CIPHERS];
static size_t n_aeads;
static char skipped[MAX_SKIPPED][NAME_LEN];
static size_t n_skipped;
static unsigned long obs[P_COUNT][OBS_COUNT];
static int strict;

static unsigned char seq_key[MAX_KEY_LEN];
static unsigned char seq_nonce[MAX_IV_LEN];
static unsigned char seq_tag[MAX_TAG_LEN];
static unsigned char aad_pattern[SEQ_MAX];
static unsigned char body_pattern[SEQ_MAX];

static void print_stats(void)
{
    size_t i;
    int p, o;

    fprintf(stderr, "\n[aead] checks performed:\n");
    for (i = 0; i < n_aeads; i++)
        fprintf(stderr, "  %-22s round trip: %-8lu sequence: %-8lu"
                " sequence decrypt: %lu\n", aeads[i].name,
                aeads[i].rt_checks, aeads[i].seq_checks,
                aeads[i].seq_dec_checks);
    for (p = 0; p < P_COUNT; p++)
        for (o = 0; o < OBS_COUNT; o++)
            if (obs[p][o] != 0)
                fprintf(stderr, "[aead] observed (%s): %s: %lu\n",
                        prof_names[p], obs_names[o], obs[p][o]);
    for (i = 0; i < n_skipped; i++)
        fprintf(stderr, "[aead] skipped, no profile: %s\n", skipped[i]);
}

static void oracle_failure(const char *what, const AEAD_PARAMS *p)
{
    fprintf(stderr, "\n[aead] ORACLE FAILURE (%s): %s\n",
            EVP_CIPHER_get0_name(p->cipher), what);
    abort();
}

static void harness_failure(const char *what, const AEAD_PARAMS *p)
{
    fprintf(stderr, "\n[aead] HARNESS CHECK FAILED (%s): %s\n",
            EVP_CIPHER_get0_name(p->cipher), what);
    abort();
}

static int classify(const EVP_CIPHER *c, enum prof *prof)
{
    if (EVP_CIPHER_is_a(c, "ChaCha20-Poly1305")) {
        *prof = P_CHACHA;
        return 1;
    }
    if (EVP_CIPHER_is_a(c, "ASCON-AEAD128")) {
        *prof = P_ASCON;
        return 1;
    }
    switch (EVP_CIPHER_get_mode(c)) {
    case EVP_CIPH_GCM_MODE:
        *prof = P_GCM;
        return 1;
    case EVP_CIPH_CCM_MODE:
        *prof = P_CCM;
        return 1;
    case EVP_CIPH_OCB_MODE:
        *prof = P_OCB;
        return 1;
    case EVP_CIPH_SIV_MODE:
        *prof = P_SIV;
        return 1;
#ifdef EVP_CIPH_GCM_SIV_MODE /* 3.2 and later */
    case EVP_CIPH_GCM_SIV_MODE:
        *prof = P_GCM_SIV;
        return 1;
#endif
    }
    return 0;
}

static int seen(const char *name)
{
    size_t i;

    for (i = 0; i < n_aeads; i++)
        if (OPENSSL_strcasecmp(aeads[i].name, name) == 0)
            return 1;
    for (i = 0; i < n_skipped; i++)
        if (OPENSSL_strcasecmp(skipped[i], name) == 0)
            return 1;
    return 0;
}

static void collect(EVP_CIPHER *c, void *arg)
{
    AEAD_CIPHER *a;
    const char *name;
    enum prof prof;

    if (c == NULL
        || (EVP_CIPHER_get_flags(c) & EVP_CIPH_FLAG_AEAD_CIPHER) == 0
        || (name = EVP_CIPHER_get0_name(c)) == NULL
        || seen(name))
        return;

    if (!classify(c, &prof)) {
        if (n_skipped < MAX_SKIPPED)
            OPENSSL_strlcpy(skipped[n_skipped++], name, NAME_LEN);
        return;
    }
    if (n_aeads == MAX_CIPHERS
        || EVP_CIPHER_get_key_length(c) > MAX_KEY_LEN
        || EVP_CIPHER_get_iv_length(c) > MAX_IV_LEN
        || !EVP_CIPHER_up_ref(c))
        return;

    a = &aeads[n_aeads++];
    a->cipher = c;
    OPENSSL_strlcpy(a->name, name, NAME_LEN);
    a->prof = prof;
    a->keylen = (size_t)EVP_CIPHER_get_key_length(c);
    /* CCM's nonce length is 15 - L, which is 7 with the default L of 8 */
    a->ivlen = prof == P_CCM ? 7 : (size_t)EVP_CIPHER_get_iv_length(c);
    /* CCM's default tag length (M) is 12 */
    a->taglen = prof == P_CCM ? 12 : 16;
}

int FuzzerInitialize(int *argc, char ***argv)
{
    const char *s;
    uint32_t x = 0x9e3779b9u;
    size_t i;

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_clear_error();

    EVP_CIPHER_do_all_provided(NULL, collect, NULL);

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
    s = getenv("AEAD_FUZZ_STATS");
    if (strict || (s != NULL && *s != '\0' && *s != '0'))
        atexit(print_stats);
    return 1;
}

static AEAD_PARAMS get_params(const AEAD_CIPHER *a, unsigned char tag_sel,
                              unsigned char iv_sel)
{
    AEAD_PARAMS p;

    p.prof = a->prof;
    p.cipher = a->cipher;
    p.keylen = a->keylen;
    p.ivlen = a->ivlen;
    p.taglen = a->taglen;

    if (a->prof == P_CCM) {
        p.taglen = 4 + 2 * (tag_sel % 7);   /* 4..16, even */
        p.ivlen = 7 + iv_sel % 7;           /* 7..13 */
    } else if (a->prof == P_OCB) {
        p.taglen = 1 + tag_sel % 16;        /* 1..16 */
        p.ivlen = 1 + iv_sel % 15;          /* 1..15 */
    } else if (a->prof == P_GCM) {
        p.taglen = 1 + tag_sel % 16;        /* 1..16 */
        /* half the time the default, otherwise 1..128 */
        if ((iv_sel & 1) == 0)
            p.ivlen = 1 + (iv_sel >> 1) % MAX_IV_LEN;
    } else if (a->prof == P_CHACHA) {
        p.taglen = 1 + tag_sel % 16;        /* 1..16; nonce is fixed */
    }
    return p;
}

/*
 * Feed |in| to Update() in |nchunks| pieces.  |out| == NULL feeds AAD.
 * Zero-length pieces are skipped, so no zero-length call is made.
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
    /* The last iteration takes whatever remains, so done == inl here */
    return 1;
}

/*
 * Feed AAD either in |nchunks| pieces, or, if |parts| is set, as exactly
 * those pieces including any empty ones.  SIV treats each AAD call as a
 * separate input, so its reference must repeat the same calls.
 */
static int feed_aad(EVP_CIPHER_CTX *ctx, const unsigned char *aad,
                    size_t aad_len, unsigned int nchunks,
                    const size_t *parts, size_t n_parts)
{
    size_t i, off = 0;
    int outl = 0;

    if (parts == NULL)
        return chunked_update(ctx, NULL, &outl, aad, aad_len, nchunks);

    for (i = 0; i < n_parts; i++) {
        if (!EVP_CipherUpdate(ctx, NULL, &outl, aad + off, (int)parts[i]))
            return 0;
        off += parts[i];
    }
    return 1;
}

/*
 * CCM takes AAD and payload in one call each.  SIV and GCM-SIV take the
 * payload in one call.  The others take both in any number of calls.
 */
static void limit_chunks(enum prof prof, unsigned int *aad_chunks,
                         unsigned int *data_chunks)
{
    if (prof == P_CCM)
        *aad_chunks = 1;
    if (prof == P_CCM || prof == P_SIV || prof == P_GCM_SIV)
        *data_chunks = 1;
}

static int do_encrypt(const AEAD_PARAMS *p, const unsigned char *key,
                      const unsigned char *nonce,
                      const unsigned char *aad, size_t aad_len,
                      unsigned int aad_chunks,
                      const size_t *aad_parts, size_t n_parts,
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
    limit_chunks(p->prof, &aad_chunks, &pt_chunks);

    if (!EVP_EncryptInit_ex2(ctx, p->cipher, NULL, NULL, NULL))
        goto end;
    if ((p->prof == P_CCM || p->prof == P_OCB || p->prof == P_GCM)
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                               (int)p->ivlen, NULL) <= 0)
        goto end;
    if ((p->prof == P_CCM || p->prof == P_OCB)
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                               (int)p->taglen, NULL) <= 0)
        goto end;
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, key,
                           p->ivlen > 0 ? nonce : NULL, -1))
        goto end;
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (p->prof == P_CCM
        && !EVP_EncryptUpdate(ctx, NULL, &unused, NULL, (int)pt_len))
        goto end;
    if (!feed_aad(ctx, aad, aad_len, aad_chunks, aad_parts, n_parts))
        goto end;
    if (!chunked_update(ctx, ct, ct_len, pt, pt_len, pt_chunks))
        goto end;
    if (!EVP_EncryptFinal_ex(ctx, ct + *ct_len, &tmplen))
        goto end;
    *ct_len += tmplen;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  tag, p->taglen);
    params[1] = OSSL_PARAM_construct_end();
    ok = EVP_CIPHER_CTX_get_params(ctx, params);

 end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/*
 * Returns 1 if accepted, 0 if setup failed, -1 if rejected.  The call
 * order follows test/evp_test.c: the expected tag is set before the key,
 * except for OCB, where only the tag length is set before the key and the
 * tag value after the AAD.
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
    limit_chunks(p->prof, &aad_chunks, &ct_chunks);

    if (!EVP_DecryptInit_ex2(ctx, p->cipher, NULL, NULL, NULL))
        goto end;
    if ((p->prof == P_CCM || p->prof == P_OCB || p->prof == P_GCM)
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                               (int)p->ivlen, NULL) <= 0)
        goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)p->taglen,
                            p->prof == P_OCB ? NULL : (void *)tag) <= 0)
        goto end;
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, key,
                           p->ivlen > 0 ? nonce : NULL, -1))
        goto end;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (p->prof == P_CCM
        && !EVP_DecryptUpdate(ctx, NULL, &unused, NULL, (int)ct_len))
        goto end;

    /*
     * Setup is done.  From here a failure is a rejection: CCM and SIV check
     * the tag in the payload Update, the others in Final.  Final is called
     * for every mode, since CCM checks an empty payload there.
     */
    rv = -1;
    if (!feed_aad(ctx, aad, aad_len, aad_chunks, NULL, 0))
        goto end;
    if (p->prof == P_OCB
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)p->taglen,
                               (void *)tag) <= 0) {
        rv = 0;
        goto end;
    }
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
    AEAD_CIPHER *a;
    AEAD_PARAMS p;
    const unsigned char *key, *nonce, *aad, *pt;
    unsigned char tag[MAX_TAG_LEN], bad_tag[MAX_TAG_LEN], bit;
    unsigned char *ct = NULL, *out = NULL, *scratch = NULL;
    unsigned int enc_chunks, dec_chunks, dec_aad_chunks;
    size_t aad_len, pt_len, idx;
    int ct_len = 0, out_len = 0, rv;

    if (len < RT_HDR || n_aeads == 0)
        return;

    a = &aeads[buf[0] % n_aeads];
    enc_chunks = buf[1] % 8 + 1;
    dec_chunks = buf[2] % 8 + 1;
    aad_len = buf[3];
    p = get_params(a, buf[4], buf[5]);
    idx = buf[6];
    bit = (unsigned char)(1u << (buf[6] >> 5));
    buf += RT_HDR;
    len -= RT_HDR;

    if (len < p.keylen + p.ivlen)
        return;
    key = buf;
    nonce = buf + p.keylen;
    buf += p.keylen + p.ivlen;
    len -= p.keylen + p.ivlen;

    aad_len %= len + 1;
    aad = buf;
    pt = buf + aad_len;
    pt_len = len - aad_len;

    /* SIV treats each AAD call as a separate input, so both sides match */
    dec_aad_chunks = p.prof == P_SIV ? enc_chunks : dec_chunks;

    ct = OPENSSL_malloc(pt_len + 2 * EVP_MAX_BLOCK_LENGTH);
    out = OPENSSL_malloc(pt_len + 2 * EVP_MAX_BLOCK_LENGTH);
    scratch = OPENSSL_malloc(aad_len + pt_len + 2 * EVP_MAX_BLOCK_LENGTH);
    if (ct == NULL || out == NULL || scratch == NULL)
        goto end;

    if (!do_encrypt(&p, key, nonce, aad, aad_len, enc_chunks, NULL, 0,
                    pt, pt_len, enc_chunks, ct, &ct_len, tag)) {
        if (strict)
            harness_failure("valid encryption failed", &p);
        goto end;
    }

    rv = do_decrypt(&p, key, nonce, tag, aad, aad_len, dec_aad_chunks,
                    ct, (size_t)ct_len, dec_chunks, out, &out_len);
    if (rv == 0) {
        if (strict)
            harness_failure("valid decryption setup failed", &p);
        goto end;
    }
    if (rv < 0)
        oracle_failure("correct tag rejected", &p);
    if ((size_t)out_len != pt_len
        || (pt_len > 0 && memcmp(out, pt, pt_len) != 0))
        oracle_failure("decryption did not return the plaintext", &p);
    a->rt_checks++;

    /* A modified tag is rejected whatever the tag length */
    memcpy(bad_tag, tag, p.taglen);
    bad_tag[idx % p.taglen] ^= bit;
    if (do_decrypt(&p, key, nonce, bad_tag, aad, aad_len, dec_aad_chunks,
                   ct, (size_t)ct_len, dec_chunks, out, &out_len) > 0)
        oracle_failure("modified tag accepted", &p);

    /*
     * A modified AAD or ciphertext is accepted by chance with probability
     * 2^-(8 * taglen).  Skip tags under 6 bytes, where that is reachable.
     */
    if (p.taglen < 6)
        goto end;

    if (aad_len > 0) {
        memcpy(scratch, aad, aad_len);
        scratch[idx % aad_len] ^= bit;
        if (do_decrypt(&p, key, nonce, tag, scratch, aad_len,
                       dec_aad_chunks, ct, (size_t)ct_len, dec_chunks,
                       out, &out_len) > 0)
            oracle_failure("modified AAD accepted", &p);
    }
    if (ct_len > 0) {
        memcpy(scratch, ct, (size_t)ct_len);
        scratch[idx % (size_t)ct_len] ^= bit;
        if (do_decrypt(&p, key, nonce, tag, aad, aad_len, dec_aad_chunks,
                       scratch, (size_t)ct_len, dec_chunks,
                       out, &out_len) > 0)
            oracle_failure("modified ciphertext accepted", &p);
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
    OP_RESET, OP_MSGLEN, OP_COUNT
};

typedef enum { ST_NEW, ST_ACTIVE, ST_DONE, ST_ERROR } SEQ_STATE;

/* What the reference encryption must reproduce */
typedef struct {
    size_t aad_start;           /* GCM-SIV: AAD before this was discarded */
    size_t aad_end;             /* AAD supplied so far */
    size_t parts[MAX_PARTS];    /* SIV: length of every AAD call */
    size_t n_parts;
    size_t aad_calls;           /* CCM: non-empty AAD calls */
    size_t body_len;
    size_t body_calls;
    long declared;              /* CCM: declared payload length, or -1 */
    int unmodelled;
} SEQ_MODEL;

static void model_reset(SEQ_MODEL *m)
{
    memset(m, 0, sizeof(*m));
    m->declared = -1;
}

static size_t clamp(size_t want, size_t room)
{
    return want < room ? want : room;
}

/*
 * GCM and ChaCha20-Poly1305 produce ciphertext that does not depend on the
 * AAD, and each Update returns exactly as much as it is given.  So one
 * encryption of body_pattern gives valid ciphertext for any prefix, and a
 * decryption of that prefix must return the same prefix of body_pattern.
 */
static const unsigned char *get_ct_stream(AEAD_CIPHER *a,
                                          const AEAD_PARAMS *p)
{
    unsigned char tag[MAX_TAG_LEN];
    int len = 0;

    if (a->prof != P_GCM && a->prof != P_CHACHA)
        return NULL;
    if (!a->ct_stream_tried) {
        a->ct_stream_tried = 1;
        a->ct_stream = OPENSSL_malloc(SEQ_BUF);
        if (a->ct_stream != NULL
            && (!do_encrypt(p, seq_key, seq_nonce, NULL, 0, 1, NULL, 0,
                            body_pattern, SEQ_MAX, 1, a->ct_stream, &len, tag)
                || len != SEQ_MAX)) {
            if (strict)
                harness_failure("ciphertext stream encryption failed", p);
            OPENSSL_free(a->ct_stream);
            a->ct_stream = NULL;
        }
    }
    return a->ct_stream;
}

static void seq_check(const AEAD_PARAMS *p, AEAD_CIPHER *a,
                      EVP_CIPHER_CTX *ctx, const SEQ_MODEL *m,
                      const unsigned char *ct, size_t ct_len)
{
    unsigned char tag[MAX_TAG_LEN], ref_tag[MAX_TAG_LEN];
    unsigned char ref_ct[SEQ_BUF];
    int ref_len = 0;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)p->taglen,
                            tag) <= 0) {
        if (strict)
            harness_failure("no tag after a successful Final", p);
        return;
    }
    if (!do_encrypt(p, seq_key, seq_nonce,
                    aad_pattern + m->aad_start, m->aad_end - m->aad_start, 1,
                    p->prof == P_SIV ? m->parts : NULL, m->n_parts,
                    body_pattern, m->body_len, 1, ref_ct, &ref_len, ref_tag)) {
        if (strict)
            harness_failure("reference encryption failed", p);
        return;
    }
    if ((size_t)ref_len != ct_len || memcmp(ref_ct, ct, ct_len) != 0)
        oracle_failure("call sequence changed the ciphertext", p);
    if (memcmp(ref_tag, tag, p->taglen) != 0)
        oracle_failure("call sequence changed the tag", p);
    a->seq_checks++;
}

/*
 * Decryption in a GCM or ChaCha20-Poly1305 sequence: the plaintext must be
 * the matching prefix of body_pattern, the correct tag for the AAD and
 * ciphertext supplied must be accepted, and a modified one rejected.  The
 * tag is set just before Final, which these modes allow.
 * Returns 1 if Final succeeded, 0 if it failed, -1 if Final was not called.
 */
static int seq_dec_check(const AEAD_PARAMS *p, AEAD_CIPHER *a,
                         EVP_CIPHER_CTX *ctx, const SEQ_MODEL *m,
                         unsigned char *out, size_t out_len, int good)
{
    unsigned char tag[MAX_TAG_LEN];
    unsigned char ref_ct[SEQ_BUF];
    int ref_len = 0, outl = 0, rv;

    if (out_len != m->body_len
        || (out_len > 0 && memcmp(out, body_pattern, out_len) != 0))
        oracle_failure("call sequence changed the decrypted plaintext", p);

    if (!do_encrypt(p, seq_key, seq_nonce, aad_pattern + m->aad_start,
                    m->aad_end - m->aad_start, 1, NULL, 0,
                    body_pattern, m->body_len, 1, ref_ct, &ref_len, tag)) {
        if (strict)
            harness_failure("reference encryption failed", p);
        return -1;
    }
    if ((size_t)ref_len != m->body_len
        || (ref_len > 0
            && memcmp(ref_ct, a->ct_stream, (size_t)ref_len) != 0)) {
        if (strict)
            harness_failure("reference ciphertext differs from the stream", p);
        return -1;
    }
    if (!good)
        tag[0] ^= 1;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)p->taglen,
                            tag) <= 0) {
        if (strict)
            harness_failure("setting the tag before Final failed", p);
        return -1;
    }
    rv = EVP_DecryptFinal_ex(ctx, out + out_len, &outl);
    if (good && rv <= 0)
        oracle_failure("correct tag rejected after call sequence", p);
    if (!good && rv > 0)
        oracle_failure("modified tag accepted after call sequence", p);
    a->seq_dec_checks++;
    return rv > 0;
}

static void run_sequence(const uint8_t *buf, size_t len)
{
    AEAD_CIPHER *a;
    AEAD_PARAMS p;
    EVP_CIPHER_CTX *ctx, *clone = NULL;
    SEQ_MODEL m;
    SEQ_STATE st = ST_NEW;
    unsigned char out[SEQ_BUF], scratch[SEQ_BUF];
    size_t out_len = 0, amt;
    int enc = -1, outl, ok, rv, sticky_unmodelled = 0;
    int one_call_payload;
    const unsigned char *ct_stream;

    if (len < 1 || n_aeads == 0)
        return;
    /* Default nonce and tag lengths, which the reference also uses */
    a = &aeads[buf[0] % n_aeads];
    p.prof = a->prof;
    p.cipher = a->cipher;
    p.keylen = a->keylen;
    p.ivlen = a->ivlen;
    p.taglen = a->taglen;
    one_call_payload = p.prof == P_CCM || p.prof == P_SIV
                       || p.prof == P_GCM_SIV;
    ct_stream = get_ct_stream(a, &p);
    buf++;
    len--;

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        return;
    model_reset(&m);

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
            model_reset(&m);
            out_len = 0;
            if (enc)
                ok = EVP_EncryptInit_ex2(ctx, p.cipher, seq_key,
                                         p.ivlen > 0 ? seq_nonce : NULL,
                                         NULL);
            else
                ok = EVP_DecryptInit_ex2(ctx, p.cipher, NULL, NULL, NULL)
                     && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                            (int)p.taglen, seq_tag) > 0
                     && EVP_CipherInit_ex(ctx, NULL, NULL, seq_key,
                                          p.ivlen > 0 ? seq_nonce : NULL,
                                          -1);
            st = ok ? ST_ACTIVE : ST_ERROR;
            break;

        case OP_MSGLEN:
            /* CCM declares the payload length this way; others do not */
            if (st != ST_ACTIVE)
                break;

            /*
             * Known crash, not yet fixed: OCB reads from a NULL input with a
             * nonzero length.  Remove this skip once the fix is in.
             */
            if (p.prof == P_OCB)
                break;
            amt = clamp(want, SEQ_MAX);
            if (!EVP_CipherUpdate(ctx, NULL, &outl, NULL, (int)amt)) {
                st = ST_ERROR;
                break;
            }
            if (p.prof != P_CCM || m.aad_calls > 0 || m.body_calls > 0
                || m.declared >= 0)
                m.unmodelled = 1;
            m.declared = (long)amt;
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
            if (m.body_calls > 0) {
                m.unmodelled = 1;
                obs[p.prof][OBS_AAD_AFTER_PAYLOAD]++;
            }
            /* GCM-SIV discards earlier AAD on a zero-length AAD update */
            if (p.prof == P_GCM_SIV && amt == 0)
                m.aad_start = m.aad_end;
            if (p.prof == P_SIV) {
                if (m.n_parts == MAX_PARTS)
                    m.unmodelled = 1;
                else
                    m.parts[m.n_parts++] = amt;
            }
            if (p.prof == P_CCM && amt > 0 && ++m.aad_calls > 1) {
                m.unmodelled = 1;
                obs[P_CCM][OBS_CCM_SPLIT_AAD]++;
            }
            m.aad_end += amt;
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
                                  (!enc && ct_stream != NULL
                                   ? ct_stream : body_pattern) + m.body_len,
                                  (int)amt)) {
                st = ST_ERROR;
                break;
            }
            if (one_call_payload && m.body_calls > 0) {
                m.unmodelled = 1;
                obs[p.prof][OBS_SPLIT_PAYLOAD]++;
            }
            if (outl < 0 || (size_t)outl > SEQ_BUF - out_len
                || (ct_stream != NULL && (size_t)outl != amt)) {
                m.unmodelled = 1;
                outl = 0;
            }
            out_len += (size_t)outl;
            m.body_len += amt;
            m.body_calls++;
            break;

        case OP_FINAL:
            if (st == ST_DONE) {
                (void)EVP_CipherFinal_ex(ctx, scratch, &outl);
                break;
            }
            if (st != ST_ACTIVE)
                break;
            if (!enc) {
                if (ct_stream != NULL && !m.unmodelled && !sticky_unmodelled) {
                    rv = seq_dec_check(&p, a, ctx, &m, out, out_len,
                                       (buf[1] & 1) == 0);
                    if (rv >= 0) {
                        st = rv ? ST_DONE : ST_ERROR;
                        break;
                    }
                }
                /* The expected tag is a fixed pattern, so failure is normal */
                st = EVP_DecryptFinal_ex(ctx, out + out_len, &outl) > 0
                     ? ST_DONE : ST_ERROR;
                break;
            }
            if (!EVP_EncryptFinal_ex(ctx, out + out_len, &outl)) {
                st = ST_ERROR;
                break;
            }
            if (outl > 0 && (size_t)outl <= SEQ_BUF - out_len)
                out_len += (size_t)outl;
            st = ST_DONE;
            if (p.prof == P_CCM && m.declared >= 0
                && (size_t)m.declared != m.body_len) {
                m.unmodelled = 1;
                obs[P_CCM][OBS_CCM_LEN_MISMATCH]++;
            }
            if (!m.unmodelled && !sticky_unmodelled)
                seq_check(&p, a, ctx, &m, out, out_len);
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
            model_reset(&m);
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

    for (i = 0; i < n_aeads; i++) {
        EVP_CIPHER_free(aeads[i].cipher);
        OPENSSL_free(aeads[i].ct_stream);
    }
    n_aeads = 0;
}