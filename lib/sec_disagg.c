#include "sec_disagg.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

static void print_bytes(void *buf, size_t count) {
    unsigned char *bytes = buf;
    for (size_t i = 0; i < count; ++i)
	printf("%x", *(bytes + i));
}

struct disagg_crypto disagg_crypto_global;

size_t disagg_mmio_decrypt(void *buf, size_t count) {
    /*
     * Debugging
     */
    printf("disagg_mmio_decrypt:\n"
	    "Whole message: 0x");
    print_bytes(disagg_crypto_global.buf, disagg_crypto_global.adlen + count + disagg_crypto_global.authsize);
    printf("\nAD (counter): 0x");
    print_bytes(disagg_crypto_global.buf, disagg_crypto_global.adlen);
    printf("\ncipher-size (only encrypted data): %ld\n"
	    "ciphertext: 0x", count);
    print_bytes(disagg_crypto_global.buf + disagg_crypto_global.adlen, count);
    printf("\nAuth Tag: 0x");
    print_bytes(disagg_crypto_global.buf + disagg_crypto_global.adlen + count, disagg_crypto_global.authsize);
    /*
     *
     */

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int outlen;
    OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};

    if (!(ctx = EVP_CIPHER_CTX_new())) { 
	goto err;
    }

    if (!(cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL))) {
	goto err;
    }
    
    // Set key and iv
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &disagg_crypto_global.ivlen);
    if (!EVP_DecryptInit_ex2(ctx, cipher, disagg_crypto_global.key, disagg_crypto_global.iv, params)) {
	printf("Error: DecryptInit failed\n");
	goto err;
    }

    // Set the counter as AD
    if (!EVP_DecryptUpdate(ctx, NULL, &outlen, disagg_crypto_global.buf, disagg_crypto_global.adlen)) {
	printf("disagg_mmio_decrypt: DecryptUpdate 1 failed\n");
	goto err;
    }

    // Set the ciphertext
    if (!EVP_DecryptUpdate(ctx, buf, &outlen, disagg_crypto_global.buf + disagg_crypto_global.adlen, count)) {
	printf("disagg_mmio_decrypt: DecryptUdpate 2 failed\n");
	goto err;
    }

    // Set auth tag
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, disagg_crypto_global.buf + count + disagg_crypto_global.adlen, disagg_crypto_global.authsize);
    if (!EVP_CIPHER_CTX_set_params(ctx, params)) {
	printf("disagg_mmio_decrypt: set_params failed\n");
	goto err;
    }

    /*
     * Debugging
     */
    printf("\nPlaintext: 0x");
    print_bytes(buf, count);
    printf("\n\n");
    /*
     *
     */

    // Finalise and check if auth tag matches
    if (EVP_DecryptFinal_ex(ctx, buf, &outlen) <= 0) {
	printf("\ndisagg_mmio_decrypt: AUTH failed\n");
	goto err;
    }

    // Check if counter matches
    if (disagg_crypto_global.counter != *((uint64_t *) disagg_crypto_global.buf)) {
	printf("disagg_mmio_decrypt: counter does not match\n");
	goto err;
    }
    ++disagg_crypto_global.counter;

    return count;
err:
    if (cipher)
	EVP_CIPHER_free(cipher);
    if (ctx)
	EVP_CIPHER_CTX_free(ctx);
    return 0;
}

void *disagg_mmio_encrypt(void *buf, size_t count) {
    /*
     * Debugging
     */
    printf("disagg_mmio_encrypt:\n"
	    "Plaintext: 0x");
    print_bytes(buf, count);
    printf("\n");
    /*
     *
     */

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int outlen;
    OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};

    if (!(ctx = EVP_CIPHER_CTX_new())) { 
	goto err;
    }

    if (!(cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL))) {
	goto err;
    }
    
    // Set key and iv for both ctxs and ciphers
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &disagg_crypto_global.ivlen);
    if (!EVP_EncryptInit_ex2(ctx, cipher, disagg_crypto_global.key, disagg_crypto_global.iv, params)) {
	printf("Error: EncryptInit failed\n");
	goto err;
    }

    // Set the counter as AD
    disagg_crypto_global.adlen = sizeof(disagg_crypto_global.counter);
    if (!EVP_EncryptUpdate(ctx, NULL, &outlen, (unsigned char *)&disagg_crypto_global.counter, disagg_crypto_global.adlen)) {
	printf("disagg_mmio_encrypt: EncryptUpdate 1 failed\n");
	goto err;
    }
    *((uint64_t *)disagg_crypto_global.buf) = disagg_crypto_global.counter;

    // Set the plaintext
    if (!EVP_EncryptUpdate(ctx, disagg_crypto_global.buf + disagg_crypto_global.adlen, &outlen, buf, count)) {
	printf("disagg_mmio_encrypt: EncryptUdpate 2 failed\n");
	goto err;
    }

    // Finalise
    if (!EVP_EncryptFinal_ex(ctx, NULL, &outlen)) {
	printf("disagg_mmio_encrypt: EncryptFinal failed\n");
	goto err;
    }

    // Write Authentication code into output buf
    disagg_crypto_global.authsize = 16;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, 
	    disagg_crypto_global.buf + disagg_crypto_global.adlen + count, disagg_crypto_global.authsize);
    if (!EVP_CIPHER_CTX_get_params(ctx, params)) {
	printf("disagg_mmio_encrypt: get_params for auth tag failed\n");
	goto err;
    }

    /*
     * Debugging
     */
    printf("AD (counter): 0x");
    print_bytes(disagg_crypto_global.buf, disagg_crypto_global.adlen);
    printf("\ncipher-size (only encrypted data): %ld\n"
	    "ciphertext: 0x", count);
    print_bytes(disagg_crypto_global.buf + disagg_crypto_global.adlen, count);
    printf("\nAuth Tag: 0x");
    print_bytes(disagg_crypto_global.buf + disagg_crypto_global.adlen + count, disagg_crypto_global.authsize);
    printf("\n\n");
    /*
     *
     */

    ++disagg_crypto_global.counter;
    return disagg_crypto_global.buf;
err:
    if (cipher)
	EVP_CIPHER_free(cipher);
    if (ctx)
	EVP_CIPHER_CTX_free(ctx);
    return NULL;
}

int disagg_init_crypto(void) {
    disagg_crypto_global.counter = 0;

    disagg_crypto_global.buf = malloc(256);
    if (!disagg_crypto_global.buf) {
	printf("disagg_init_crypto: malloc failed\n");
	goto err;
    }

    // Init IV
    disagg_crypto_global.ivlen = 12; // this is what /include/crypto/gcm.h says
    disagg_crypto_global.iv = malloc(disagg_crypto_global.ivlen);
    if (!disagg_crypto_global.iv) {
	printf("disagg_init_crypto: malloc failed\n");
	goto err;
    }
    memset(disagg_crypto_global.iv, 0x01, disagg_crypto_global.ivlen);

    // Init key
    disagg_crypto_global.keylen = 32; // Has to be 32 because we use AES-256
    disagg_crypto_global.key = malloc(disagg_crypto_global.keylen);
    if (!disagg_crypto_global.key) {
	printf("disagg_init_crypto: malloc failed\n");
	goto err_malloc;
    }
    memset(disagg_crypto_global.key, 0x00, disagg_crypto_global.keylen);


    disagg_crypto_global.counter = 0;
    disagg_crypto_global.authsize = 16;
    disagg_crypto_global.adlen = sizeof(disagg_crypto_global.counter);
    return 0;
err_malloc:
    free(disagg_crypto_global.iv);
err:
    return 1;
}

#if 0
struct disagg_crypto_type {
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher;
};

struct disagg_crypto {
    struct disagg_crypto_type crypto_enc;
    struct disagg_crypto_type crypto_dec;
    size_t ivlen;
};

struct disagg_crypto crypto;

int disagg_init_crypto()
{
    unsigned char *key;
    int keylen;
    unsigned char *iv;
    struct disagg_crypto_type *crypto_enc = &crypto.crypto_enc;
    struct disagg_crypto_type *crypto_dec = &crypto.crypto_dec;
    OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};

    printf("Initializing the crypto structures\n");

    if (!(crypto_enc->ctx = EVP_CIPHER_CTX_new()) ||
	!(crypto_dec->ctx = EVP_CIPHER_CTX_new())) {
	goto err;
    }

    if (!(crypto_enc->cipher == EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)) ||
	!(crypto_dec->cipher == EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL))) {
	goto err;
    }

    // Init IV
    crypto.ivlen = 12; // this is what /include/crypto/gcm.h says
    iv = malloc(crypto.ivlen);
    if (!iv) {
	printf("Error: malloc failed\n");
	goto err;
    }
    memset(iv, 0x01, crypto.ivlen);
		       
    // Init key
    keylen = 32; // Has to be 32 because we use AES-256
    key = malloc(keylen);
    if (!key) {
	printf("Error: malloc failed\n");
	goto err_malloc;
    }
    memset(key, 0x00, keylen);

    // Set key and iv for both ctxs and ciphers
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &crypto.ivlen);
    if (!EVP_EncryptInit_ex2(crypto_enc->ctx, crypto_enc->cipher, key, iv, params) ||
	!EVP_EncryptInit_ex2(crypto_dec->ctx, crypto_dec->cipher, key, iv, params)) {
	printf("Error: EncryptInit failed\n");
	goto err_malloc;
    }


    return 0;
err_malloc:
    free(iv);
err:
    EVP_CIPHER_free(crypto_enc->cipher);
    EVP_CIPHER_free(crypto_dec->cipher);
    EVP_CIPHER_CTX_free(crypto_enc->ctx);
    EVP_CIPHER_CTX_free(crypto_dec->ctx);
    return 1;
}
#endif
