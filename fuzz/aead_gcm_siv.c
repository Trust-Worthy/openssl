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
 * Fuzz AES-256-GCM-SIV (RFC 8452) round-trip behaviour.
 *
 * fuzz/provider.c's do_evp_cipher() only ever calls EncryptInit ->
 * EncryptUpdate (once, on a fixed 4-byte plaintext) -> EncryptFinal. It
 * never decrypts, never sets AAD, never reads or checks a tag, and never
 * splits input across multiple Update calls. This harness targets exactly
 * those gaps for AES-256-GCM-SIV:
 *
 *   - fuzzer-controlled key, nonce, AAD and plaintext
 *   - plaintext/AAD split across a fuzzer-controlled number of Update calls
 *     on both the encrypt and (independently) the decrypt side
 *   - a metamorphic oracle: decrypt(encrypt(pt)) must equal pt exactly.
 *     ASan/UBSan alone can't catch a "decrypts successfully but returns
 *     the wrong plaintext" bug -- this harness aborts if that ever happens.
 *   - an auth-bypass oracle: corrupting one byte of the tag must cause
 *     decryption to fail. This harness aborts if a corrupted tag is ever
 *     wrongly accepted.
 *
 * The tag is read/written via the OSSL_PARAM interface
 * (OSSL_CIPHER_PARAM_AEAD_TAG through EVP_CIPHER_CTX_get/set_params)
 * rather than the legacy EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_*_TAG) calls,
 * to stay consistent with the OSSL_PARAM-based style used elsewhere in
 * this project's evp_aead_test.c, and because it's the more future-proof
 * of the two equivalent interfaces.
 */

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "fuzzer.h"

#define KEY_LEN   32 /* AES-256 */
#define NONCE_LEN 12 /* RFC 8452 */
#define TAG_LEN   16 /* RFC 8452 */

static EVP_CIPHER *aes_256_gcm_siv;

int FuzzerInitialize(int *argc, char ***argv)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_clear_error();

    aes_256_gcm_siv = EVP_CIPHER_fetch(NULL, "AES-256-GCM-SIV", NULL);

    return aes_256_gcm_siv != NULL;
}

/*
 * Feed `in` (length inl) to Update() in `nchunks` fuzzer-chosen pieces
 * instead of one call. Works for both AAD (out == NULL) and plaintext/
 * ciphertext (out != NULL). Naturally handles inl == 0 (zero-length AAD
 * or plaintext) by simply doing nothing, and handles nchunks > inl by
 * collapsing down to fewer effective calls -- no special-casing needed.
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
        size_t remaining = inl - done;
        size_t take = remaining / (nchunks - i);
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

/* Read the current tag out of an encrypt context via OSSL_PARAM. */
static int get_tag(EVP_CIPHER_CTX *ctx, unsigned char *tag)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                    tag, TAG_LEN);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_CIPHER_CTX_get_params(ctx, params);
}

/* Tell a decrypt context which tag to expect, via OSSL_PARAM. */
static int set_tag(EVP_CIPHER_CTX *ctx, const unsigned char *tag)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                    (void *)tag, TAG_LEN);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_CIPHER_CTX_set_params(ctx, params);
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    const unsigned char *key, *nonce, *aad, *pt;
    size_t aad_len, pt_len;
    unsigned int enc_chunks, dec_chunks;
    unsigned char aad_ctrl;
    unsigned char *ct = NULL, *decrypted = NULL, *bad_out = NULL, tag[TAG_LEN];
    int ct_len = 0, decrypted_len = 0, tmplen = 0, unused = 0;
    EVP_CIPHER_CTX *enc_ctx = NULL, *dec_ctx = NULL;

    if (aes_256_gcm_siv == NULL)
        return 0;

    /* key + nonce + 3 control bytes (enc_chunks, dec_chunks, aad split) */
    if (len < KEY_LEN + NONCE_LEN + 3)
        return 0;

    key = buf;   buf += KEY_LEN;   len -= KEY_LEN;
    nonce = buf; buf += NONCE_LEN; len -= NONCE_LEN;

    enc_chunks = (buf[0] % 8) + 1;
    dec_chunks = (buf[1] % 8) + 1;
    aad_ctrl   = buf[2];
    buf += 3; len -= 3;

    /* aad_len can land anywhere from 0 to len, so both "all AAD, no
     * plaintext" and "no AAD, all plaintext" get explored. */
    aad_len = aad_ctrl % (len + 1);
    aad = buf;
    pt = buf + aad_len;
    pt_len = len - aad_len;

    ct = OPENSSL_malloc(pt_len + EVP_MAX_BLOCK_LENGTH);
    decrypted = OPENSSL_malloc(pt_len + EVP_MAX_BLOCK_LENGTH);
    /* Dedicated scratch buffer for the corrupted-tag decrypt attempt below,
     * sized the same as `decrypted` -- deliberately never reuses `decrypted`
     * itself, so that block can never clobber the already-verified
     * plaintext regardless of how these blocks get reordered later. */
    bad_out = OPENSSL_malloc(pt_len + EVP_MAX_BLOCK_LENGTH);
    enc_ctx = EVP_CIPHER_CTX_new();
    dec_ctx = EVP_CIPHER_CTX_new();

    if (ct == NULL || decrypted == NULL || bad_out == NULL
        || enc_ctx == NULL || dec_ctx == NULL)
        goto err;

    /* --- Encrypt --- */
    if (!EVP_EncryptInit_ex2(enc_ctx, aes_256_gcm_siv, key, nonce, NULL))
        goto err;

    if (!chunked_update(enc_ctx, NULL, &unused, aad, aad_len, enc_chunks))
        goto err;

    if (!chunked_update(enc_ctx, ct, &ct_len, pt, pt_len, enc_chunks))
        goto err;

    if (!EVP_EncryptFinal_ex(enc_ctx, ct + ct_len, &tmplen))
        goto err;
    ct_len += tmplen;

    if (!get_tag(enc_ctx, tag))
        goto err;

    /* --- Decrypt with the correct tag: must succeed and match exactly --- */
    if (!EVP_DecryptInit_ex2(dec_ctx, aes_256_gcm_siv, key, nonce, NULL))
        goto err;

    unused = 0;
    if (!chunked_update(dec_ctx, NULL, &unused, aad, aad_len, dec_chunks))
        goto err;

    if (!chunked_update(dec_ctx, decrypted, &decrypted_len, ct,
                         (size_t)ct_len, dec_chunks))
        goto err;

    if (!set_tag(dec_ctx, tag))
        goto err;

    if (EVP_DecryptFinal_ex(dec_ctx, decrypted + decrypted_len, &tmplen) <= 0) {
        /* A correct tag was rejected. Real bug: false-negative auth. */
        abort();
    }
    decrypted_len += tmplen;

    /* Metamorphic oracle: decrypt(encrypt(pt)) must equal pt exactly. */
    if ((size_t)decrypted_len != pt_len
        || (pt_len > 0 && memcmp(decrypted, pt, pt_len) != 0)) {
        abort();
    }

    /* --- Decrypt with a corrupted tag: must fail --- */
    {
        EVP_CIPHER_CTX *bad_ctx = EVP_CIPHER_CTX_new();
        unsigned char bad_tag[TAG_LEN];
        int bad_len = 0, bad_tmplen = 0, bad_unused = 0;

        if (bad_ctx != NULL) {
            memcpy(bad_tag, tag, TAG_LEN);
            bad_tag[0] ^= 0xff;

            if (EVP_DecryptInit_ex2(bad_ctx, aes_256_gcm_siv, key, nonce, NULL)
                && chunked_update(bad_ctx, NULL, &bad_unused, aad, aad_len, dec_chunks)
                && chunked_update(bad_ctx, bad_out, &bad_len, ct,
                                   (size_t)ct_len, dec_chunks)
                && set_tag(bad_ctx, bad_tag)
                && EVP_DecryptFinal_ex(bad_ctx, bad_out + bad_len, &bad_tmplen) > 0) {
                /* A corrupted tag was ACCEPTED. Real bug: auth bypass. */
                abort();
            }
            EVP_CIPHER_CTX_free(bad_ctx);
        }
    }

err:
    EVP_CIPHER_CTX_free(enc_ctx);
    EVP_CIPHER_CTX_free(dec_ctx);
    OPENSSL_free(ct);
    OPENSSL_free(decrypted);
    OPENSSL_free(bad_out);
    ERR_clear_error();

    return 0;
}

void FuzzerCleanup(void)
{
    EVP_CIPHER_free(aes_256_gcm_siv);
}