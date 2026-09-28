#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    const char *name = argc > 1 ? argv[1] : "AES-256-GCM-SIV";
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, name, NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int rv;

    if (c == NULL || ctx == NULL
        || !EVP_DecryptInit_ex2(ctx, c, NULL, NULL, NULL)) {
        fprintf(stderr, "setup failed for %s\n", name);
        return 1;
    }
    /* Tag length only: NULL pointer, valid 16-byte length */
    rv = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL);
    printf("%-18s SET_TAG(16, NULL) on decrypt returned %d\n", name, rv);
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    return 0;
}