/*
 * Tests whether AES-256-GCM-SIV decrypt requires evp_test.c's exact
 * two-stage init sequence: Init(cipher only, no key/IV) -> SET_TAG via
 * ctrl -> Init(key+IV, cipher=NULL) -> Update -> Final. This is NOT the
 * same as "set tag before Update with a single Init call" -- the tag is
 * set BEFORE the key/IV are even installed.
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

/*
 * Decrypt using evp_test.c's exact two-stage init ordering:
 *   1. Init with cipher type only (key=NULL, iv=NULL)
 *   2. SET_TAG via EVP_CIPHER_CTX_ctrl
 *   3. Second Init call (cipher=NULL) to install key+iv
 *   4. set_padding(0)
 *   5. Update(ciphertext)
 *   6. Final
 */
static int decrypt_evptest_order(EVP_CIPHER *cipher,
                                  const unsigned char *key,
                                  const unsigned char *iv,
                                  const unsigned char *ct, int ct_len,
                                  const unsigned char *tag, size_t tag_len,
                                  unsigned char *out, int *out_len,
                                  const char *label)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ol = 0, tl = 0;
    int ok = 0;

    if (ctx == NULL) {
        printf("%-45s CTX ALLOC FAILED\n", label);
        return 0;
    }

    /* Stage 1: cipher type only, no key/iv yet */
    if (!EVP_CipherInit_ex2(ctx, cipher, NULL, NULL, 0 /* decrypt */, NULL)) {
        printf("%-45s STAGE1 INIT FAILED\n", label);
        goto done;
    }

    /* Set tag BEFORE key/iv are installed -- matches evp_test.c exactly */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                             (int)tag_len, (void *)tag) <= 0) {
        printf("%-45s SET_TAG (early) FAILED\n", label);
        goto done;
    }

    /* Stage 2: install key + iv (cipher=NULL keeps the current cipher) */
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, -1)) {
        printf("%-45s STAGE2 INIT (key/iv) FAILED\n", label);
        goto done;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0); /* matches evp_test.c */

    if (!EVP_DecryptUpdate(ctx, out, &ol, ct, ct_len)) {
        printf("%-45s DECRYPT UPDATE FAILED\n", label);
        goto done;
    }

    if (EVP_DecryptFinal_ex(ctx, out + ol, &tl) <= 0) {
        printf("%-45s FAIL: tag rejected\n", label);
        goto done;
    }
    ol += tl;
    *out_len = ol;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
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
    unsigned char out[32];
    int out_len = 0;

    if (cipher == NULL) {
        printf("CIPHER FETCH FAILED\n");
        return 1;
    }

    printf("=== Decrypt RFC known-good ciphertext, evp_test.c's exact init order ===\n");
    if (decrypt_evptest_order(cipher, key, iv, expected_ct, sizeof(expected_ct),
                               expected_tag, sizeof(expected_tag),
                               out, &out_len, "KAT ciphertext")) {
        if ((size_t)out_len == sizeof(pt) && memcmp(out, pt, sizeof(pt)) == 0)
            printf("RESULT: OK -- correct plaintext recovered\n");
        else
            printf("RESULT: WRONG PLAINTEXT RECOVERED\n");
    }

    printf("\n=== Same ordering, real key/nonce, varying length (own encrypt+decrypt) ===\n");
    {
        unsigned char buf[64], c[128], t[16];
        size_t lens[] = { 1, 2, 3, 8, 15, 16, 17, 32 };
        size_t i;

        memset(buf, 0x41, sizeof(buf));
        for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
            EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
            int cl = 0, tl = 0, pass = 0;
            OSSL_PARAM g[2];
            char label[45];

            snprintf(label, sizeof(label), "len=%zu", lens[i]);

            if (e != NULL
                && EVP_EncryptInit_ex2(e, cipher, key, iv, NULL)
                && EVP_EncryptUpdate(e, c, &cl, buf, (int)lens[i])
                && EVP_EncryptFinal_ex(e, c + cl, &tl)) {
                cl += tl;
                g[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, t, 16);
                g[1] = OSSL_PARAM_construct_end();
                if (EVP_CIPHER_CTX_get_params(e, g)) {
                    unsigned char dec_out[128];
                    int dec_out_len = 0;

                    if (decrypt_evptest_order(cipher, key, iv, c, cl, t, 16,
                                               dec_out, &dec_out_len, label)) {
                        pass = ((size_t)dec_out_len == lens[i]
                                && memcmp(dec_out, buf, lens[i]) == 0);
                    }
                }
            }
            printf("%-45s %s\n", label, pass ? "OK" : "FAIL");
            EVP_CIPHER_CTX_free(e);
        }
    }

    EVP_CIPHER_free(cipher);
    return 0;
}