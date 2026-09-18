/*
 * Checks our exact EVP_CIPHER_fetch/EncryptInit/EncryptUpdate/EncryptFinal/
 * get_tag call sequence against a known-good RFC 8452 test vector already
 * present (and presumably passing) in
 * test/recipes/30-test_evp_data/evpciph_aes_gcm_siv.txt, lines 286-292.
 *
 * If this FAILS: our own reproducer/harness's *sequence of API calls* is
 * wrong somehow (missing a step evp_test.c does differently), independent
 * of key material.
 * If this PASSES (exact byte match) but the all-zero-key sweep still
 * fails: the bug is specific to degenerate (all-zero) key/nonce material,
 * not a general GCM-SIV break.
 *
 * Also runs a controlled follow-up: same real (non-degenerate) key/nonce
 * as the KAT vector, varying ONLY the plaintext length. This isolates
 * whether short-length failures are about length specifically, or were
 * actually about the all-zero key/nonce used in earlier testing.
 *
 * Build:  cc -I include kat_check.c libcrypto.a -o kat_check
 * Run:    ./kat_check
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

static void print_hex(const char *label, const unsigned char *buf, size_t len)
{
    size_t i;

    printf("%s: ", label);
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

int main(void)
{
    /* From evpciph_aes_gcm_siv.txt, line 286-292: known-good, no AAD */
    unsigned char key[32] = {
        0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    unsigned char iv[12] = {
        0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    unsigned char pt[16] = {
        0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };
    unsigned char expected_ct[16] = {
        0x85,0xa0,0x1b,0x63,0x02,0x5b,0xa1,0x9b,0x7f,0xd3,0xdd,0xfc,
        0x03,0x3b,0x3e,0x76
    };
    unsigned char expected_tag[16] = {
        0xc9,0xea,0xc6,0xfa,0x70,0x09,0x42,0x70,0x2e,0x90,0x86,0x23,
        0x83,0xc6,0xc3,0x66
    };

    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM-SIV", NULL);
    EVP_CIPHER_CTX *enc = EVP_CIPHER_CTX_new();
    unsigned char ct[32], tag[16];
    int ct_len = 0, tmplen = 0;
    OSSL_PARAM gp[2];
    int ct_ok, tag_ok;

    if (cipher == NULL || enc == NULL) {
        printf("SETUP FAILED\n");
        return 1;
    }

    if (!EVP_EncryptInit_ex2(enc, cipher, key, iv, NULL)
        || !EVP_EncryptUpdate(enc, ct, &ct_len, pt, sizeof(pt))
        || !EVP_EncryptFinal_ex(enc, ct + ct_len, &tmplen)) {
        printf("ENCRYPT CALL FAILED (not even a wrong-answer -- a hard failure)\n");
        return 1;
    }
    ct_len += tmplen;

    gp[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                               tag, sizeof(tag));
    gp[1] = OSSL_PARAM_construct_end();
    if (!EVP_CIPHER_CTX_get_params(enc, gp)) {
        printf("GET_TAG FAILED\n");
        return 1;
    }

    ct_ok = (ct_len == (int)sizeof(expected_ct))
            && memcmp(ct, expected_ct, sizeof(expected_ct)) == 0;
    tag_ok = memcmp(tag, expected_tag, sizeof(expected_tag)) == 0;

    print_hex("got ciphertext     ", ct, ct_len);
    print_hex("expected ciphertext", expected_ct, sizeof(expected_ct));
    print_hex("got tag            ", tag, sizeof(tag));
    print_hex("expected tag       ", expected_tag, sizeof(expected_tag));

    printf("\nCiphertext match: %s\n", ct_ok ? "YES" : "NO");
    printf("Tag match:        %s\n", tag_ok ? "YES" : "NO");

    EVP_CIPHER_CTX_free(enc);

    printf("\n=== Does DECRYPT accept the RFC's own known-good ciphertext+tag? ===\n");
    {
        EVP_CIPHER_CTX *d = EVP_CIPHER_CTX_new();
        unsigned char out[32];
        int ol = 0, tl = 0;
        OSSL_PARAM s[2];
        unsigned char tag_copy[16];

        memcpy(tag_copy, expected_tag, 16);
        s[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  tag_copy, 16);
        s[1] = OSSL_PARAM_construct_end();

        if (d != NULL
            && EVP_DecryptInit_ex2(d, cipher, key, iv, NULL)
            && EVP_DecryptUpdate(d, out, &ol, expected_ct, sizeof(expected_ct))
            && EVP_CIPHER_CTX_set_params(d, s)
            && EVP_DecryptFinal_ex(d, out + ol, &tl) > 0) {
            ol += tl;
            if ((size_t)ol == sizeof(pt) && memcmp(out, pt, sizeof(pt)) == 0)
                printf("DECRYPT OF KNOWN-GOOD CIPHERTEXT: OK\n");
            else
                printf("DECRYPT OF KNOWN-GOOD CIPHERTEXT: WRONG PLAINTEXT RECOVERED\n");
        } else {
            printf("DECRYPT OF KNOWN-GOOD CIPHERTEXT: FAILED (tag rejected or a call failed)\n");
        }
        EVP_CIPHER_CTX_free(d);
    }

    printf("\n=== Same real key/nonce as the KAT vector, varying length only ===\n");
    {
        unsigned char buf[64];
        size_t lens[] = { 1, 2, 3, 8, 15, 16, 17, 32 };
        size_t i;

        memset(buf, 0x41, sizeof(buf));
        for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
            EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
            EVP_CIPHER_CTX *d = EVP_CIPHER_CTX_new();
            unsigned char c[128], out[128], t[16];
            int cl = 0, ol = 0, tl = 0;
            OSSL_PARAM g[2], s[2];
            int pass = 0;

            if (EVP_EncryptInit_ex2(e, cipher, key, iv, NULL)
                && EVP_EncryptUpdate(e, c, &cl, buf, (int)lens[i])
                && EVP_EncryptFinal_ex(e, c + cl, &tl)) {
                cl += tl;
                g[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, t, 16);
                g[1] = OSSL_PARAM_construct_end();
                if (EVP_CIPHER_CTX_get_params(e, g)
                    && EVP_DecryptInit_ex2(d, cipher, key, iv, NULL)
                    && EVP_DecryptUpdate(d, out, &ol, c, cl)) {
                    s[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, t, 16);
                    s[1] = OSSL_PARAM_construct_end();
                    if (EVP_CIPHER_CTX_set_params(d, s)
                        && EVP_DecryptFinal_ex(d, out + ol, &tl) > 0) {
                        ol += tl;
                        pass = ((size_t)ol == lens[i] && memcmp(out, buf, lens[i]) == 0);
                    }
                }
            }
            printf("len=%-3zu %s\n", lens[i], pass ? "OK" : "FAIL");
            EVP_CIPHER_CTX_free(e);
            EVP_CIPHER_CTX_free(d);
        }
    }

    EVP_CIPHER_free(cipher);
    return (ct_ok && tag_ok) ? 0 : 1;
}