#ifndef SEC_DISAGG_H
#define SEC_DISAGG_H

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

struct disagg_crypto {
    unsigned char *buf;
    unsigned char *key;
    int keylen;
    unsigned char *iv;
    size_t ivlen;
    uint64_t *counter;
    int authsize;
    size_t adlen;
};

extern struct disagg_crypto disagg_crypto_global;

int disagg_init_crypto();
void *disagg_mmio_encrypt(void *buf, size_t count);

// Expects the encrypted input in disagg_crypto_global.buf
size_t disagg_mmio_decrypt(void *buf, size_t count);

#endif // SEC_DISAGG_H
