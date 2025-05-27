#ifndef SEC_DISAGG_H
#define SEC_DISAGG_H

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

struct disagg_crypto_mmio {
    unsigned char *buf;
    unsigned char *key;
    int keylen;
    unsigned char *iv;
    size_t ivlen;
    uint64_t *counter;
    int authsize;
    size_t adlen;
};

struct disagg_crypto_dma {
    void *proxyDMA_start;
    unsigned char *key;
    int keylen;
    unsigned char *iv;
    size_t ivlen;
    uint64_t *counter;
    int authsize;
    size_t adlen;
};

extern struct disagg_crypto_mmio disagg_crypto_mmio_global;
extern struct disagg_crypto_dma disagg_crypto_dma_global;

int disagg_init_crypto();

void *disagg_mmio_encrypt(void *buf, size_t count);

// Expects the encrypted input in disagg_crypto_global.buf
size_t disagg_mmio_decrypt(void *buf, size_t count);

size_t disagg_dma_decrypt(void *from, void *to, size_t count);
int disagg_dma_encrypt(void *from, void *to, size_t count);

#endif // SEC_DISAGG_H
