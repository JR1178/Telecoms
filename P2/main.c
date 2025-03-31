#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define MAJOR(x,y,z) ((x&y) ^ (x&z) ^ (y&z))

// sizes
#define R1_SZ 19
#define R2_SZ 22
#define R3_SZ 23
#define KEY_SZ 64
#define FRAME_SZ 22
#define STREAM_SZ 228

// clock & masks positions
#define R1_CLK 8
#define R2_CLK 10
#define R3_CLK 10
#define R1_MASK 0x7FFFF
#define R2_MASK 0x3FFFFF
#define R3_MASK 0x7FFFFF

// Globals
uint32_t R1=0, R2=0, R3=0;
uint8_t keystream[STREAM_SZ];


void clock_maj() {
    bool m = MAJOR((R1>>R1_CLK)&1, (R2>>R2_CLK)&1, (R3>>R3_CLK)&1);
    // clock R1
    bool fb = ((R1>>13)&1) ^ ((R1>>16)&1) ^ ((R1>>17)&1) ^ ((R1>>18)&1);
    if(((R1 >> R1_CLK)&1) == m)
        R1 = ((R1<<1) & R1_MASK) | fb;
    
    // clock R2
    fb = ((R2>>20)&1) ^ ((R2>>21)&1);
    if (((R2>>R2_CLK)&1) == m)
        R2 = ((R2<<1)&R2_MASK) | fb;

    // clock R3
    fb = ((R3>>7)&1) ^ ((R3>>20)&1) ^ ((R3>>21)&1) ^ ((R3>>22)&1);
    if (((R3>>R3_CLK)&1) == m)
        R3 = ((R3<<1)&R3_MASK) | fb;
}

void clock_all() {
    bool fb = ((R1>>13)&1) ^ ((R1>>16)&1) ^ ((R1>>17)&1) ^ ((R1>>18)&1);
    R1 = ((R1<<1)&R1_MASK) | fb;

    fb = ((R2 >> 20)&1) ^ ((R2>>21)&1);
    R2 = ((R2<<1)&R2_MASK) | fb;

    fb = ((R3>>7)&1) ^ ((R3>>20)&1) ^ ((R3>>21)&1) ^ ((R3>>22)&1);
    R3 = ((R3<<1)&R3_MASK) | fb;
}

void a51(uint64_t key, uint32_t frame, uint8_t *msg, int msg_len, uint8_t *out) {
    R1 = 0, R2 = 0, R3 = 0;
    memset(keystream, 0, STREAM_SZ);

    //load key
    for(int i=0; i<KEY_SZ; i++) {
        bool b = (key >> i)&1;
        R1 ^= b;
        R2 ^= b;
        R3 ^= b;
        clock_all();
    }

    //load frame
    for(int i=0; i<FRAME_SZ; i++) {
        bool b = (frame >> i)&1;
        R1 ^= b;
        R2 ^= b;
        R3 ^= b;
        clock_all();
    }

    // warmup regs
    for (int i = 0; i < 100; i++)
        clock_maj();

    //generate keystream
    for (int i=0; i<STREAM_SZ; i++) {
        clock_maj();
        keystream[i] = ((R1>>18)&1) ^ ((R2>>21)&1) ^ ((R3>>22)&1);
    }

    // encryption/decrypt
    for (int i = 0; i < msg_len; i++)       
        out[i] = msg[i] ^ keystream[i];
}

int main() {
    uint8_t msg[12] = "Hello World!";
    uint64_t key = 0x1F3F5F7F9FBFDFFF;
    uint32_t frame = 0x3BFADC;
    
    uint8_t cipher[12];
    memset(cipher, 0, sizeof(cipher));
    uint8_t pltxt[12];
    memset(pltxt, 0, sizeof(pltxt));

    puts("******** Simple A5/1 Demo **********");
    printf("64b Key: 0x%02lX\nFrame:   0x%02X\n",key,frame);
    printf("Original Message:  %s 0x", msg);
    for(int i=0; i<sizeof(msg); i++)
        printf("%02X", msg[i]);

    a51(key, frame, msg, sizeof(msg), cipher);
    
    printf("\nEncrypted Message: ");
    for(int i=0; i<sizeof(cipher); i++) printf("%c", cipher[i]);
    printf(" 0x");
    for(int i=0; i<sizeof(cipher); i++) printf("%02X", cipher[i]);

    a51(key, frame, cipher, sizeof(cipher), pltxt);

    printf("\nDecrypted Message: ");
    for(int i=0; i<sizeof(pltxt); i++) printf("%c", pltxt[i]);
    printf(" 0x");
    for(int i=0; i<sizeof(pltxt); i++) printf("%02X", pltxt[i]);

    // brute forcing EC msg
    char decision[2] = "";
    printf("\n\nBrute Force EC message? (y/n) ");
    scanf("%s", decision);
    if(strncmp(decision, "n", 1) == 0) {
        printf("Exiting...\n");
        return 0;
    } else {
        // init vars
        uint8_t cT[26] = {0x54,0x68,0x69,0x73,0x20,0x69,0x73,0x20,
                           0x6d,0x79,0x20,0x73,0x65,0x63,0x72,0x65,
                           0x74,0x20,0x6d,0x65,0x73,0x73,0x61,0x67,
                           0x65,0x21};
        uint8_t pT[26];
        memset(pT, 0, sizeof(pT));
        
        printf("Cipher text is: 0x");
        for(int i=0; i<sizeof(cT); i++) {
            printf("%02X",cT[i]);
        }
        
        key = 0x10; // no point in starting w/0x0 0x0 (no encryption)
        while(key < 0xFFFFFFFFFFFFFFFF){
            frame = 0x0;
            while(frame < 0x3FFFFF){
                a51(key, frame, cT, sizeof(cT), pT);
                if(strncmp(((char *)pT+'\0'),((char *)cT+'\0'), sizeof(pT)) == 0) {
                    //msg decripted
                    printf("\n Plain text is: %s\n key: 0x%016lX\n frame: 0x%08X\n",((char *)pT+'\0'),key,frame);
                    return 0;
                }
                memset(pT,0,sizeof(pT));
                frame += 0x1;
            }
            key += 0x1;
        }
        return 1; // msg not decrypted
    }
}