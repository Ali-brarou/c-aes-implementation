#include <stdio.h> 
#include <stdlib.h> 
#include <sys/random.h> 

#include "aes.h"


int main(void)
{
    /* https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf */ 
    AES_ctx context; 
    uint8_t key[AES_KEY_SIZE] = {
        0x54, 0x68, 0x61, 0x74,   // 'T' 'h' 'a' 't'
        0x73, 0x20, 0x6D, 0x79,   // 's' ' ' 'm' 'y'
        0x20, 0x4B, 0x75, 0x6E,   // ' ' 'K' 'u' 'n'
        0x67, 0x20, 0x46, 0x75,   // 'g' ' ' 'F' 'u'
    }; 
    AES_ctx_init(&context, AES_MODE_ECB, key); 
    
    uint8_t test_in[AES_BLOCK_SIZE * 2] = {
        0x54, 0x77, 0x6F, 0x20,   // T w o  
        0x4F, 0x6E, 0x65, 0x20,   // O n e  
        0x4E, 0x69, 0x6E, 0x65,   // N i n e
        0x20, 0x54, 0x77, 0x6F,    //   T w o
        0x54, 0x77, 0x6F, 0x20,   // T w o  
        0x4F, 0x6E, 0x65, 0x20,   // O n e  
        0x4E, 0x69, 0x6E, 0x65,   // N i n e
        0x20, 0x54, 0x77, 0x6F    //   T w o
    };
    uint8_t test_out[AES_BLOCK_SIZE * 2]; 

    AES_encrypt(&context, test_in, test_out, 32); 

    puts("this is the key : "); 
    for (int i = 0; i < 16; i++)
    {
        printf("%02X", key[i]); 
    }
    puts("\n"); 
    puts("this is the expanded key : "); 
    for (int i = 0; i < 176; i++)
    {
        printf("%02X", context.round_keys[i]); 
    }
    puts("\n"); 
    puts("this is the input buffer : "); 
    for (int i = 0; i < 32; i++)
    {
        printf("%02X", test_in[i]); 
    }
    puts("\n"); 
    puts("this is the output buffer : "); 
    for (int i = 0; i < 32; i++)
    {
        printf("%02X", test_out[i]); 
    }
    puts("\n"); 

    AES_decrypt(&context, test_out, test_in, 32); 
    puts("this is decrypted input buffer : "); 
    for (int i = 0; i < 32; i++)
    {
        printf("%02X", test_in[i]); 
    }
    puts("\n"); 

    return 0; 
}
