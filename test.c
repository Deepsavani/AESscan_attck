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

typedef uint8_t state_t[4][4];

static void phex(uint8_t* str);
static void test_encrypt_ecb_verbose(void);
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

static void test_encrypt_ecb_verbose(void)
{
    // Example of more verbose verification

    uint8_t i,j,wrap_b[16][2], b[2],key_pos[16][2];
    
    // 128bit key
    uint8_t key[16] = { (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
    // 512bit text
    struct AES_ctx ctx;
    struct AES_ctx ctx_check;
        AES_init_ctx(&ctx, key);


    // uint8_t temp[32] = {        (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
    //                             (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
    //                             (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
    //                             (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00};

    
uint8_t rk[16],rk1[16];
uint8_t a,x,y,m,z, plain_text[32],rk0[16],rk0_2[32],new_text[32],old_text[32];
uint8_t encrypt_new[32],encrypt_previous[32],xor[32],check_test[32];
for(x=(uint8_t)0; x<(uint8_t)16; x++){ 
    uint8_t temp[32] = {        (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
                                (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
                                (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
                                (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00};
                                
    memcpy(plain_text, temp, 16);
    memcpy(check_test , temp, 16);
    for(y=(uint8_t)0; y<=(uint8_t)254; y++){
        AES_init_ctx(&ctx, key);  /// EXPAND THE KEY
        a=0; 
        // printf("OLD Input text : \n ");
        // phex(plain_text);
        memcpy(old_text, plain_text, 16);   // COPY THE STRING PLAIN_TEXT TO OLD_TEXT
        AES_ECB_encrypt_scan(&ctx, plain_text); //GET THE STATE AFTER ROUND1 IN PLAIN_TEXT
        memcpy(encrypt_previous, plain_text, 16);    // COPY THE STRING PLAIN_TEXT TO ENCRYPT_PREVIOUS
        temp[x]=temp[x]+(0x01); // Increment 1st byte of the input by 1.
        //abc[x] = temp[x]+(0x02);
        memcpy(plain_text, temp, 16);
        // printf(" NEW Input text : \n ");
        // phex(plain_text);
        memcpy(new_text, plain_text, 16);
        AES_ECB_encrypt_scan(&ctx, plain_text); // RUN encryption again.
        memcpy(encrypt_new, plain_text, 16);
        temp[x]=temp[x]+(0x01); // Increment - So that we have pair (f0,f1), (f2,f3),...
        memcpy(plain_text, temp, 16);
        // printf("encrypt new=\n");
        // phex(encrypt_new);
        // printf("encrypt previous=\n");
        // phex(encrypt_previous);
        for(i=0;i<16;i++)           //////   ------  XOR  
        {
            xor[i]=encrypt_new[i]^encrypt_previous[i];
        }
        // printf("Ye XOR hai\n");
        // phex(xor);

        for(i=0; i<16; i++){ //// CHECK FOR NUMBER OF 1S
            for(j=0;j<8;j++){
            if(xor[i]&1){ // AND THE LSB WITH 1 AND CHECK IF IT'S ONE. IF SO, INCREMENT COUNTER.
                a++; 
            }
            xor[i]>>=1; // RIGTH SHIFT
            
        }
        }
        // printf("\nNumber of ones = ");
        // printf("%d\n",a);
        
        if(a==9){                //  --- CHECK FOR A MATCH.
            // wrap_b[x][0] = 226; 
            // wrap_b[x][1] = 227;
            // printf("\n a value = %.2x\n",new_text[x]);
            key_pos[x][0]=(new_text[x])^(0xE2); // XOR WITH THE CORRESPOONDING INPUT AND PUT IT IN A 2D ARRAY
            key_pos[x][1]=(new_text[x])^(0xE3);
            printf("\n------------------------break -----------------------\n");
            break;
        }
        else if(a==12){
            printf("\n a value = %.2x\n",new_text[x]);
            key_pos[x][0]=(new_text[x])^(0xF2);
            key_pos[x][1]=(new_text[x])^(0xF3);
            //printf("%s", *wrap_b);
            printf("\n------------------------break -----------------------\n");
            break;
        }
        else if(a==23){
            // wrap_b[x][0] = 122;
            // wrap_b[x][1] = 123;
            printf("\n a value = %.2x\n",new_text[x]);
            key_pos[x][0]=(new_text[x])^(0x7a);
            key_pos[x][1]=(new_text[x])^(0x7b);
            //printf("%.2x", *wrap_b);
            printf("\n------------------------break -----------------------\n");
            break;
        }
        else if(a==24){
            // wrap_b[x][0] = 130;
            // wrap_b[x][1] = 131;
            printf("\n a value = %.2x\n",new_text[x]);
            key_pos[x][0]=(new_text[x])^(0x82);
            key_pos[x][1]=(new_text[x])^(0x83);
            //printf("%s", *wrap_b);
            printf("\n------------------------break -----------------------\n");
            break;
            }
        else{
            // temp[x]=temp[x]+(0x01);
            // memcpy(plain_text, temp, 16);
            continue;
        }
    }

    continue;
}
printf("TWO POSSIBLE VALUES FOR EACH BYTE :\n");
//---------------------------------- print possinble values of b
for(i=0;i<16;i++){
    for(j=0;j<2;j++){
        printf("%.2x ", key_pos[i][j]);
        if(j==1){
            printf("\n"); 
        }
    }
}

// ---------------BRUTTE FORCE THE KEY------------
// uint8_t in_check[32] = {        (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
//                                 (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
//                                 (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
//                                 (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00};
// memcpy(check_test , in_check, 16);
//     for(z=0;z<pow(2,16);z++) {
// 	if(z & 0x1)
// 	    rk[0]=rk0[0];
// 	else
// 	    rk[0]=rk1[0];
// 	if(z & 0x2)
// 	    rk[1]=rk0[1];
// 	else
// 	    rk[1]=rk1[1];
// 	if(z & 0x4)
// 	    rk[2]=rk0[2];
// 	else
// 	    rk[2]=rk1[2];
// 	if(z & 0x8)
// 	    rk[3]=rk0[3];
// 	else
// 	    rk[3]=rk1[3];
// 	if(z & 0x10)
// 	    rk[4]=rk0[4];
// 	else
// 	    rk[4]=rk1[4];
// 	if(z & 0x20)
// 	    rk[5]=rk0[5];
// 	else
// 	    rk[5]=rk1[5];
// 	if(z & 0x40)
// 	    rk[6]=rk0[6];
// 	else
// 	    rk[6]=rk1[6];
// 	if(z & 0x80)
// 	    rk[7]=rk0[7];
// 	else
// 	    rk[7]=rk1[7];
// 	if(z & 0x100)
// 	    rk[8]=rk0[8];
// 	else
// 	    rk[8]=rk1[8];
// 	if(z & 0x200)
// 	    rk[9]=rk0[9];
// 	else
// 	    rk[9]=rk1[9];
// 	if(z & 0x400)
// 	    rk[10]=rk0[10];
// 	else
// 	    rk[10]=rk1[10];
// 	if(z & 0x800)
// 	    rk[11]=rk0[11];
// 	else
// 	    rk[11]=rk1[11];
// 	if(z & 0x1000)
// 	    rk[12]=rk0[12];
// 	else
// 	    rk[12]=rk1[12];
// 	if(z & 0x2000)
// 	    rk[13]=rk0[13];
// 	else
// 	    rk[13]=rk1[13];
// 	if(z & 0x4000)
// 	    rk[14]=rk0[14];
// 	else
// 	    rk[14]=rk1[14];
// 	if(z & 0x8000)
// 	    rk[15]=rk0[15];
// 	else
// 	    rk[15]=rk1[15];

// 	uint8_t loop=0;
// 	//printf(" = RK \n");
// 	AES_init_ctx(&ctx_check, rk);
// 	AES_ECB_encrypt_scan(&ctx_check,in_check);
// 	AES_ECB_encrypt_scan(&ctx,check_test);
// 	for(i=0;i<16;i++) {
// 	    if(check_test[i]==in_check[i])
// 		loop++;
// 	    //printf("%02X",rk[i]);
// 	}
// 	if(loop==16) {
// 	   printf("  RK: ");
// 	   for(i=0;i<16;i++) {
// 	       printf("%02X",rk[i]);
// 	   }
// 	   printf("    SUCCESS!!   Loop = %d\n", z);
// 	   break;
// 	}
//     }
}
