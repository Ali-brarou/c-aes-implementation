# c-aes-implementation
A lightweight implementation of the AES-128 encryption algorithm in C.

This is for educational and experimental purposes only. It is not secure for real-world cryptographic use.

### Build 
```
cd src
make
```

## Basic usage 
```
AES_ctx ctx;
uint8_t key[16] = { /* your 128-bit key */ };
uint8_t input[16] = { /* your data block */ };
uint8_t output[16];

AES_ctx_init(&ctx, AES_MODE_ECB, key);
AES_encrypt(&ctx, input, output, sizeof(input));
```
