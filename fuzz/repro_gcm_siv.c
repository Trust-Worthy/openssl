/*
 * Standalone reproducer for the AES-256-GCM-SIV decrypt-rejects-valid-tag
 * / wrong-plaintext bug found via fuzz/aead_gcm_siv.c. Deliberately NOT
 * part of the fuzz harness -- plain, direct EVP calls, so a clean
 * pass/fail here rules out any libFuzzer/harness-specific artifact
 * entirely.
 *
 * The minimized crashing input decoded to enc_chunks = dec_chunks = 7 on
 * a 1-byte plaintext. Given this harness's chunking arithmetic
 * (remaining / (nchunks - i)), that means SIX zero-length Update() calls
 * followed by ONE real Update() carrying the single plaintext byte, then
 * Final() -- not a single, whole-buffer Update() the way round_trip()
 * originally tested. round_trip_chunked() below reproduces that exact
 * call sequence; round_trip() is kept as a baseline sanity check that
 * the simple, unchunked case still works correctly.
 *
 * Build (run from the top of your openssl checkout, after it's built):
 *   cc -I include repro_gcm_siv.c libcrypto.a -o repro_gcm_siv -g -O0
 * Run:
 *   ./repro_gcm_siv
 *
 * If the linker complains about missing pthread symbols, add -lpthread.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#define KEY_LEN   32
#define NONCE_LEN 12
#define TAG_LEN   16

/*
 * Baseline: single, whole-buffer EncryptUpdate/DecryptUpdate. This is
 * the "does plain round-trip work at all" check -- expected to pass,
 * since it's the same shape as the already-fixed zero-length case and
 * evp_aead_test.c's other passing coverage.
 */
static int round_trip(const unsigned char *key, const unsigned char *nonce,
                       const unsigned char *pt, size_t pt_len,
                       const char *label)
{
    static const unsigned char dummy = 0;
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM-SIV", NULL);
    EVP_CIPHER_CTX *enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *dec = EVP_CIPHER_CTX_new();
    unsigned char ct[256], out[256], tag[TAG_LEN];
    int ct_len = 0, out_len = 0, tmplen = 0, ok = 0;
    OSSL_PARAM gp[2], sp[2];
    const unsigned char *in = (pt_len != 0) ? pt : &dummy;

    if (cipher == NULL || enc == NULL || dec == NULL) {
        printf("%-45s SETUP FAILED\n", label);
        goto done;
    }

    if (!EVP_EncryptInit_ex2(enc, cipher, key, nonce, NULL)
        || !EVP_EncryptUpdate(enc, ct, &ct_len, in, (int)pt_len)
        || !EVP_EncryptFinal_ex(enc, ct + ct_len, &tmplen)) {
        printf("%-45s ENCRYPT FAILED\n", label);
        goto done;
    }
    ct_len += tmplen;

    gp[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                               tag, TAG_LEN);
    gp[1] = OSSL_PARAM_construct_end();
    if (!EVP_CIPHER_CTX_get_params(enc, gp)) {
        printf("%-45s GET_TAG FAILED\n", label);
        goto done;
    }

    if (!EVP_DecryptInit_ex2(dec, cipher, key, nonce, NULL)
        || !EVP_DecryptUpdate(dec, out, &out_len, ct, ct_len)) {
        printf("%-45s DECRYPT UPDATE FAILED\n", label);
        goto done;
    }

    sp[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                               tag, TAG_LEN);
    sp[1] = OSSL_PARAM_construct_end();
    if (!EVP_CIPHER_CTX_set_params(dec, sp)) {
        printf("%-45s SET_TAG FAILED\n", label);
        goto done;
    }

    if (EVP_DecryptFinal_ex(dec, out + out_len, &tmplen) <= 0) {
        printf("%-45s FAIL: correct tag REJECTED (pt_len=%zu)\n",
               label, pt_len);
        goto done;
    }
    out_len += tmplen;

    if ((size_t)out_len != pt_len
        || (pt_len > 0 && memcmp(out, pt, pt_len) != 0)) {
        printf("%-45s FAIL: wrong plaintext recovered\n", label);
        goto done;
    }

    printf("%-45s OK (pt_len=%zu)\n", label, pt_len);
    ok = 1;

done:
    EVP_CIPHER_CTX_free(enc);
    EVP_CIPHER_CTX_free(dec);
    EVP_CIPHER_free(cipher);
    return ok;
}

/*
 * Reproduces the actual crashing call sequence: n_empty zero-length
 * Update() calls, THEN one real Update() carrying the whole plaintext,
 * THEN Final(). Done independently on both the encrypt and decrypt
 * sides, mirroring exactly what fuzz/aead_gcm_siv.c's chunked_update()
 * produces when nchunks is large relative to pt_len.
 */
static int round_trip_chunked(const unsigned char *key,
                               const unsigned char *nonce,
                               const unsigned char *pt, size_t pt_len,
                               unsigned int n_empty_enc,
                               unsigned int n_empty_dec,
                               const char *label)
{
    static const unsigned char dummy = 0;
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM-SIV", NULL);
    EVP_CIPHER_CTX *enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *dec = EVP_CIPHER_CTX_new();
    unsigned char ct[256], out[256], tag[TAG_LEN];
    int ct_len = 0, out_len = 0, tmplen = 0, ok = 0, dummy_outl = 0;
    unsigned int i;
    OSSL_PARAM gp[2], sp[2];
    const unsigned char *in = (pt_len != 0) ? pt : &dummy;

    if (cipher == NULL || enc == NULL || dec == NULL) {
        printf("%-45s SETUP FAILED\n", label);
        goto done;
    }

    /* --- encrypt: n_empty_enc zero-length updates, then the real one --- */
    if (!EVP_EncryptInit_ex2(enc, cipher, key, nonce, NULL)) {
        printf("%-45s ENCRYPT INIT FAILED\n", label);
        goto done;
    }
    for (i = 0; i < n_empty_enc; i++) {
        if (!EVP_EncryptUpdate(enc, ct, &dummy_outl, NULL, 0)) {
            printf("%-45s ENCRYPT EMPTY-UPDATE #%u FAILED\n", label, i);
            goto done;
        }
    }
    if (!EVP_EncryptUpdate(enc, ct, &ct_len, in, (int)pt_len)) {
        printf("%-45s ENCRYPT REAL-UPDATE FAILED\n", label);
        goto done;
    }
    if (!EVP_EncryptFinal_ex(enc, ct + ct_len, &tmplen)) {
        printf("%-45s ENCRYPT FINAL FAILED\n", label);
        goto done;
    }
    ct_len += tmplen;

    gp[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                               tag, TAG_LEN);
    gp[1] = OSSL_PARAM_construct_end();
    if (!EVP_CIPHER_CTX_get_params(enc, gp)) {
        printf("%-45s GET_TAG FAILED\n", label);
        goto done;
    }

    /* --- decrypt: n_empty_dec zero-length updates, then the real one --- */
    if (!EVP_DecryptInit_ex2(dec, cipher, key, nonce, NULL)) {
        printf("%-45s DECRYPT INIT FAILED\n", label);
        goto done;
    }
    for (i = 0; i < n_empty_dec; i++) {
        if (!EVP_DecryptUpdate(dec, out, &dummy_outl, NULL, 0)) {
            printf("%-45s DECRYPT EMPTY-UPDATE #%u FAILED\n", label, i);
            goto done;
        }
    }
    if (!EVP_DecryptUpdate(dec, out, &out_len, ct, ct_len)) {
        printf("%-45s DECRYPT REAL-UPDATE FAILED\n", label);
        goto done;
    }

    sp[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                               tag, TAG_LEN);
    sp[1] = OSSL_PARAM_construct_end();
    if (!EVP_CIPHER_CTX_set_params(dec, sp)) {
        printf("%-45s SET_TAG FAILED\n", label);
        goto done;
    }

    if (EVP_DecryptFinal_ex(dec, out + out_len, &tmplen) <= 0) {
        printf("%-45s FAIL: correct tag REJECTED (pt_len=%zu)\n",
               label, pt_len);
        goto done;
    }
    out_len += tmplen;

    if ((size_t)out_len != pt_len
        || (pt_len > 0 && memcmp(out, pt, pt_len) != 0)) {
        printf("%-45s FAIL: wrong plaintext recovered "
               "(got out_len=%d, want pt_len=%zu)\n",
               label, out_len, pt_len);
        goto done;
    }

    printf("%-45s OK (pt_len=%zu, empty_enc=%u, empty_dec=%u)\n",
           label, pt_len, n_empty_enc, n_empty_dec);
    ok = 1;

done:
    EVP_CIPHER_CTX_free(enc);
    EVP_CIPHER_CTX_free(dec);
    EVP_CIPHER_free(cipher);
    return ok;
}

int main(void)
{
    /* From crash-84baa9c...: empty plaintext, empty AAD */
    unsigned char key1[KEY_LEN] = {
        0x86,0x86,0xc1,0xc1,0xc1,0xc1,0xc1,0xc1,0x3e,0x3e,0x25,0x3e,
        0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,
        0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x2b,0x3e
    };
    unsigned char nonce1[NONCE_LEN] = {
        0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x2b
    };

    /* From the minimized 48-byte crash: 1-byte plaintext (0x3e),
     * empty AAD, enc_chunks = dec_chunks = 7 -- which this harness's
     * chunking arithmetic turns into 6 empty Updates + 1 real Update
     * on each side. This is the field's actual decoded key/nonce. */
    unsigned char key2[KEY_LEN] = {
        0x86,0x86,0xc1,0xc1,0xc1,0xc1,0xc1,0xc1,0x3e,0x3e,0x25,0x3e,
        0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,
        0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x2b,0x3e
    };
    unsigned char nonce2[NONCE_LEN] = {
        0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x2b
    };
    unsigned char pt2[1] = { 0x3e };

    unsigned char zero_key[KEY_LEN] = {0};
    unsigned char zero_nonce[NONCE_LEN] = {0};

    printf("=== Baseline: single whole-buffer Update, no chunking ===\n");
    round_trip(key1, nonce1, NULL, 0, "crash key/nonce, empty pt");
    round_trip(key2, nonce2, pt2, 1, "crash key/nonce, 1-byte pt");
    round_trip(zero_key, zero_nonce, pt2, 1, "zero key/nonce, 1-byte pt, no chunking");

    printf("\n=== Actual crash shape: 6 empty Updates then 1 real Update ===\n");
    round_trip_chunked(key2, nonce2, pt2, 1, 6, 6,
                        "crash key/nonce, 1-byte pt, 6+1 chunking");

    printf("\n=== Is this key-dependent, or fully general? ===\n");
    round_trip_chunked(zero_key, zero_nonce, pt2, 1, 6, 6,
                        "all-zero key/nonce, 1-byte pt, 6+1 chunking");

    printf("\n=== Sweep: how many leading empty Updates does it take? ===\n");
    {
        unsigned int n;

        for (n = 0; n <= 8; n++) {
            char label[45];

            snprintf(label, sizeof(label), "n_empty=%u", n);
            round_trip_chunked(zero_key, zero_nonce, pt2, 1, n, n, label);
        }
    }

    printf("\n=== Sweep: does plaintext length change the threshold? ===\n");
    {
        unsigned char buf[64];
        size_t lens[] = { 1, 2, 15, 16, 17, 31, 32, 33 };
        size_t i;
        char label[45];

        memset(buf, 0x41, sizeof(buf));
        for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
            snprintf(label, sizeof(label), "pt_len=%zu, n_empty=6", lens[i]);
            round_trip_chunked(zero_key, zero_nonce, buf, lens[i], 6, 6, label);
        }
    }

    return 0;
}