#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1
#define CBC 1
#define CTR 1
#define ECB 1

#include "aes.h"
#include "aes.c"
#include "hextobin.c"

typedef uint8_t state_t[4][4];

static void phex(uint8_t* str);
static void test_encrypt_ecb_verbose(void);
char* itoa(int value, char* result, int base) ;
int main(void)
{
    int exit;

#if defined(AES256)
    printf("\nTesting AES256\n\n");
#elif defined(AES192)
    printf("\nTesting AES192\n\n");
#elif defined(AES128)
    printf("\nTesting AES128\n\n");
#else
    printf("You need to specify a symbol between AES128, AES192 or AES256. Exiting");
    return 0;
#endif

    test_encrypt_ecb_verbose();

    return 0;
}


// prints string as hex
static void phex(uint8_t* str)
{

#if defined(AES256)
    uint8_t len = 32;
#elif defined(AES192)
    uint8_t len = 24;
#elif defined(AES128)
    uint8_t len = 16;
#endif

    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}
char* itoa(int value, char* result, int base) 
{
		// check that the base if valid
		if (base < 2 || base > 36) { *result = '\0'; return result; }

		char* ptr = result, *ptr1 = result, tmp_char;
		int tmp_value;

		do {
			tmp_value = value;
			value /= base;
			*ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz" [35 + (tmp_value - value * base)];
		} while ( value );

		// Apply negative sign
		if (tmp_value < 0) *ptr++ = '-';
		*ptr-- = '\0';
		while(ptr1 < ptr) {
			tmp_char = *ptr;
			*ptr--= *ptr1;
			*ptr1++ = tmp_char;
		}
		return result;
}
static void test_encrypt_ecb_verbose(void)
{
    // Example of more verbose verification

    uint8_t i,j,*wrap_b[16], b[2];
    
    
    // 128bit key
    uint8_t key[16] = { (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00 };
    // 512bit text
    struct AES_ctx ctx;
        AES_init_ctx(&ctx, key);

    uint8_t temp[32] = {  (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
                                (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
                                (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
                                (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00};

    

uint8_t a,x,y,m, plain_text[32];

for(x=(uint8_t)0; x<(uint8_t)16; x++){ 
    memcpy(plain_text, temp, 16);
    for(y=(uint8_t)0; y<=(uint8_t)255; y++){
        AES_ECB_encrypt(&ctx, plain_text + (i * 16));
        printf("plain_text\n");
        phex(plain_text);
        uint8_t encrypt_new[32],encrypt_previous[32],xor[32];
        unsigned char xorstring[32];
        memcpy(encrypt_previous, plain_text, 16);
        a=0; 
        long dec=0;
        temp[x]=temp[x]+(0x01);
        memcpy(plain_text, temp, 16);
        AES_ECB_encrypt(&ctx, plain_text + (i * 16));
        memcpy(encrypt_new, plain_text, 16);

        //printf("encrypt previous=\n");
        //phex(encrypt_previous);
        //printf("encrypt new=\n");
        //phex(encrypt_new);
        //memcpy(xor, (int)(encrypt_previous^encrypt_new), 16);
        //uint8_t xor = (encrypt_previous^encrypt_new);
        for(i=0;i<16;i++)
        {
            xor[i]=encrypt_new[i]^encrypt_previous[i];
            //printf("\nelement=")
        }

        //uint8_t *xor1=&xor;
        uint8_t change[16];
        printf("xor=\n");
        phex(xor);

        // xor[33]='\0';
        for(i=0; i<32; i++){
            xor[i] >>= 1;
            printf("%.2x\n", xor[i]);
        }

        }
        printf("Number of 1's :: %d\n\n", a);
        
        if(a==9){
            b[0]=226;
            b[1]=227;
            wrap_b[x] = b;
            printf("%s", *wrap_b);
            printf(".....d.....");
            break;
        }
        else if(a==12){
            b[0]=242;
            b[1]=243;
            wrap_b[x] = b;
            printf("%s", *wrap_b);
            printf("......c....");
            break;
        }
        else if(a==23){
            b[0]=122;
            b[1]=123;
            wrap_b[x] = b;
            printf("%s", *wrap_b);
            printf(".........b.");
            break;
        }
        else if(a==24){
            b[0]=130;
            b[1]=131;
            wrap_b[x] = b;
            printf("%s", *wrap_b);
            printf("..........a");
            break;
            }
        else{
            break;
        }
    }

    //continue;
}

// for(i=0;i<16;i++){
//     printf("%d", (*wrap_b)[i]);
// }

    // for(i=0; i<len(plain_text); i+=1){
    //     uint8_t new_text[64] = plain_text + 1;                         
    // print text to encrypt, key and IV
    // printf("ECB encrypt verbose:\n\n");
    // printf("plain text:\n");
 
    //     phex(plain_text + i * (uint8_t) 16);
    
    // printf("\n");

    // printf("key:\n");
    // phex(key);
    // printf("\n");

    // print the resulting cipher as 4 x 16 byte strings
    
  
    
    //uint8_t k,l;
    //c = AES_ECB_encrypt(&ctx, plain_text + (i * 16));
    //d = AES_ECB_encrypt(&ctx, plain_text_two + (i * 16));

  
    // printf("\nAfter XOR: ");

    //  for(k=0; k<4; ++k){
    //   for(l=0;l<4;++l){
    //     e.arr[k][l]=(c.arr[k][l])^(d.arr[k][l]);
    //   }
    // }

    // printf("\n");
    // for(k=0; k<4; ++k){
    //   for(l=0;l<4;++l){
    //     printf("%.2x", e.arr[k][l]);
    //   }
    // }



