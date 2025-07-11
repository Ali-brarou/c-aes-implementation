#ifndef AES_H
#define AES_H

#include <stdint.h> 
#include <string.h> 
#include <sys/types.h> 
#include <stdio.h> 

#define AES_KEY_SIZE 16 
#define AES_BLOCK_SIZE 16 
#define AES_ROUND_KEYS_SIZE 176
#define AES_N_ROUNDS 10
#define AES_WORD_SIZE 4

#define AES_IS_BLOCK_SIZE(len) ((len) % AES_BLOCK_SIZE == 0)

typedef enum AES_mode_e {
    AES_MODE_ECB,  
    AES_MODE_CBC, 
} AES_mode; 

typedef struct AES_ctx_s {
    AES_mode mode; 
    uint8_t round_keys[AES_ROUND_KEYS_SIZE]; 
    uint8_t iv[AES_BLOCK_SIZE]; /* not used in ecb mode */  
} AES_ctx; 

/*
 * AES API design inspired by Tiny AES in C (https://github.com/kokke/tiny-AES-c),
 * which is released into the public domain under the Unlicense.
 */
void AES_ctx_init(AES_ctx* context, AES_mode mode, const uint8_t* key); 
void AES_ctx_init_iv(AES_ctx* context, AES_mode mode, const uint8_t* key, const uint8_t* iv); 
void AES_ctx_set_iv(AES_ctx* context, const uint8_t* iv); 
void AES_encrypt(AES_ctx* context, const uint8_t* input, uint8_t* output, size_t len); 
void AES_decrypt(AES_ctx* context, const uint8_t* input, uint8_t* output, size_t len); 

#endif
