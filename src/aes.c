#include "aes.h"

static const uint8_t r_con[] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
}; 

static const uint8_t s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static uint8_t AES_get_s_box_value(uint8_t num) {return s_box[num];}
static uint8_t AES_get_r_con_value(uint8_t num) {return r_con[num];}

static void AES_add_round_key(uint8_t round, uint8_t* state, const uint8_t* round_keys)
{
    for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++)
        state[i] ^= round_keys[round * AES_BLOCK_SIZE + i]; 
}

static void AES_sub_bytes(uint8_t* state)
{
    for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++)
        state[i] = AES_get_s_box_value(state[i]); 
}


static void AES_shift_rows(uint8_t* state)
{
    uint8_t temp; 

    /* Row 1 */ 
    temp      = state[1];
    state[1]  = state[5];
    state[5]  = state[9];
    state[9]  = state[13];
    state[13] = temp;

    /* Row 2 */
    temp        = state[2];
    state[2]    = state[10];
    state[10]   = temp;
    temp        = state[6];
    state[6]    = state[14];
    state[14]   = temp;

    /* Row 3 */
    temp        = state[15];
    state[15]   = state[11];
    state[11]   = state[7];
    state[7]    = state[3];
    state[3]    = temp;
}

static uint8_t AES_xtime(uint8_t x) {
    return (x << 1) ^ ((x >> 7) * 0x1b); 
}

static void AES_mix_columns(uint8_t* state) {
    for (uint8_t c = 0; c < 4; ++c) {
        uint8_t* col = &state[c * 4];

        uint8_t a0 = col[0];
        uint8_t a1 = col[1];
        uint8_t a2 = col[2];
        uint8_t a3 = col[3];

        uint8_t r0 = AES_xtime(a0) ^ AES_xtime(a1) ^ a1 ^ a2 ^ a3;
        uint8_t r1 = a0 ^ AES_xtime(a1) ^ AES_xtime(a2) ^ a2 ^ a3;
        uint8_t r2 = a0 ^ a1 ^ AES_xtime(a2) ^ AES_xtime(a3) ^ a3;
        uint8_t r3 = AES_xtime(a0) ^ a0 ^ a1 ^ a2 ^ AES_xtime(a3);

        col[0] = r0;
        col[1] = r1;
        col[2] = r2;
        col[3] = r3;
    }
}


static void AES_rot_word(uint8_t* word)
{
    uint8_t t = word[0]; 
    for (uint8_t i = 0; i < AES_WORD_SIZE - 1; i++)
        word[i] = word[i+1];  
    word[AES_WORD_SIZE - 1] = t; 
}

static void AES_sub_word(uint8_t* word)
{
    for (uint8_t i = 0; i < AES_WORD_SIZE; i++)
        word[i] = AES_get_s_box_value(word[i]); 
}

static void AES_key_expansion(const uint8_t* key, uint8_t* round_keys)
{
    uint8_t temp[AES_WORD_SIZE]; 
    uint8_t r_con_index = 1; 
    uint8_t round_key_index; 

    memcpy(round_keys, key, AES_KEY_SIZE); 

    for (round_key_index = AES_KEY_SIZE; round_key_index < AES_ROUND_KEYS_SIZE; round_key_index += 4)
    {
        for (int i = 0; i < AES_WORD_SIZE; i++) 
            temp[i] = round_keys[round_key_index - 4 + i]; 
        
        /* Perform schedule core */ 
        if (round_key_index % AES_KEY_SIZE == 0)
        {
            AES_rot_word(temp); 
            AES_sub_word(temp); 
            temp[0] ^= AES_get_r_con_value(r_con_index++); 
        }

        for (int i = 0; i < AES_WORD_SIZE; i++) 
            round_keys[round_key_index + i] = temp[i] ^ round_keys[round_key_index - AES_KEY_SIZE + i];
    }
}

static void AES_block_encrypt(const uint8_t* in, uint8_t* out, const uint8_t* round_keys)
{
    memcpy(out, in, AES_BLOCK_SIZE); 

    /* Initial round key addition */  
    AES_add_round_key(0, out, round_keys); 

    for (uint8_t round = 1; round < AES_N_ROUNDS; round++)
    {
        AES_sub_bytes(out); 
        AES_shift_rows(out); 
        AES_mix_columns(out); 
        AES_add_round_key(round, out, round_keys); 
    }

    /* Final round */ 
    AES_sub_bytes(out); 
    AES_shift_rows(out); 
    AES_add_round_key(AES_N_ROUNDS, out, round_keys); 
}

void AES_ctx_init(AES_ctx* context, AES_mode mode, const uint8_t* key)
{
    memset(context, 0, sizeof(AES_ctx)); 

    context->mode = mode; 
    AES_key_expansion(key, context->round_keys); 
}

#define CHECK_LEN(len)\
    do {\
        if (!AES_IS_BLOCK_SIZE(len))\
        {\
            fprintf(stderr, "Error: invalid length size\n");\
            return;\
        }\
    } while (0)

static void AES_ecb_encrypt(const AES_ctx* ctx, const uint8_t* in, uint8_t* out, size_t len)
{
    CHECK_LEN(len); 

    /* encrypt every block independently */ 
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE)
    {
        AES_block_encrypt(&in[i], &out[i], ctx->round_keys); 
    }
}

void AES_encrypt(const AES_ctx* ctx, const uint8_t* in, uint8_t* out, size_t len)
{
    switch (ctx->mode)
    {
        case AES_MODE_ECB: 
            AES_ecb_encrypt(ctx, in, out, len); 
            break; 
        default: 
            fprintf(stderr, "Error: invalid aes mode\n"); 
            return; 
    }
}
