//
// Created by ZhengYukun on 16/4/13.
//

#include "AES.h"

void addRoundKey(uint8_t * state, uint8_t * roundKey){

    for(int i = 0;i < 16;i++){
        state[i] ^= roundKey[i];
    }
}

void subBytes(uint8_t * state){

    for(int i = 0;i < 16;i++){
        state[i] = SBox[state[i]];
    }
}

void shiftRows(uint8_t * state){
    uint8_t tmp[4];

    for(int i=0;i<4;i++){
        for(int j=0;j<4;j++) {
            tmp[j] = state[ 4 * i + (j + i) % 4];
        }
        for(int j=0;j<4;j++){
            state[i * 4 + j] = tmp[j];
        }
    }
}

uint8_t gmult(uint8_t a, uint8_t b) {
    uint8_t p = 0, i = 0, hbs = 0;

    for (i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        hbs = a & 0x80;
        a <<= 1;
        if (hbs) a ^= 0x1b; // 0000 0001 0001 1011
        b >>= 1;
    }

    return (uint8_t)p;
}

void coefMult(uint8_t *a, uint8_t *b, uint8_t *d) {

    d[0] = gmult(a[0],b[0])^gmult(a[3],b[1])^gmult(a[2],b[2])^gmult(a[1],b[3]);
    d[1] = gmult(a[1],b[0])^gmult(a[0],b[1])^gmult(a[3],b[2])^gmult(a[2],b[3]);
    d[2] = gmult(a[2],b[0])^gmult(a[1],b[1])^gmult(a[0],b[2])^gmult(a[3],b[3]);
    d[3] = gmult(a[3],b[0])^gmult(a[2],b[1])^gmult(a[1],b[2])^gmult(a[0],b[3]);
}

void mixColumns(uint8_t *state) {
    int Nb = 4;
    uint8_t a[] = {0x02, 0x01, 0x01, 0x03}; // a(x) = {02} + {01}x + {01}x2 + {03}x3
    uint8_t i, j, col[4], res[4];

    for (j = 0; j < Nb; j++) {
        for (i = 0; i < 4; i++) {
            col[i] = state[Nb*i+j];
        }

        coefMult(a, col, res);

        for (i = 0; i < 4; i++) {
            state[Nb*i+j] = res[i];
        }
    }
}

void print(uint8_t * x){
    for(int i = 0;i<16;i++){
        if(i % 4 == 0)
            printf("\n");
        printf("%2x ", x[i]);
    }
    printf("\n");
}

void keySchedule(const uint8_t _key[16]){
    uint8_t key[16];
    uint8_t roundKey[16];

    memcpy(key, _key, 16 * sizeof(uint8_t));

    for(int i=0;i<16;i++){
        rk[i] = key[i];
    }

    uint8_t tmp[4];
    for(int round = 0;round < ROUNDS;round++) {
        for (int i = 0; i < 4; i++) {
            tmp[i] = SBox[key[(i + 1) % 4 * 4 + 3]] ^ key[i * 4];
            if (i == 0) {
                tmp[i] ^= Rcon[round];
            }
            roundKey[i * 4] = tmp[i];
        }
        for (int i = 1; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                roundKey[j * 4 + i] = roundKey[j * 4 + i - 1] ^ key[j * 4 + i];
            }
        }

        memcpy(key, roundKey, 16 * sizeof(uint8_t));

        for(int i=0;i<16;i++){
            rk[(round+1)*16 + i] = key[i];
        }
    }
}

uint8_t * AES(uint8_t * plainText){
    uint8_t *state = new uint8_t[16];

    for(int j = 0;j < 16;j++){
        state[ j % 4 * 4 + j / 4] = plainText[j]; //!!!字符串
        //state[j] = plainText[j];//!!!矩阵
    }

    addRoundKey(state, (uint8_t*)rk);
    for(int j = 0;j < ROUNDS - 1;j++){  //执行前9轮
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, (uint8_t*)(rk+(j+1)*16));
    }
    //执行最后一轮
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, (uint8_t*)(rk + 16 * ROUNDS));

    uint8_t *new_state = new uint8_t[16];

    for(int i=0;i<16;i++){
        new_state[i] = state[i%4 * 4+i/4];
    }
    delete[] state;
    return new_state;
}

/*
int main1(){

    const uint8_t cipherKey[] = //"3AE11562A8F3C71A2BF6DFA1509BCAF1";     //密钥
            */
/*{ //样例密钥
                    0x2b, 0x28, 0xab, 0x09,
                    0x7e, 0xae, 0xf7, 0xcf,
                    0x15, 0xd2, 0x15, 0x4f,
                    0x16, 0xa6, 0x88, 0x3c
            };*//*

            {
                    0x3A, 0xA8, 0x2B, 0x50,
                    0xE1, 0xF3, 0xF6, 0x9B,
                    0x15, 0xC7, 0xDF, 0xCA,
                    0x62, 0x1A, 0xA1, 0xF1
            };


    const uint8_t plainText[] = "zhengyukun201101";                 //明文
            */
/*{ //样例明文
                    0x32, 0x88, 0x31, 0xe0,
                    0x43, 0x5a, 0x31, 0x37,
                    0xf6, 0x30, 0x98, 0x07,
                    0xa8, 0x8d, 0xa2, 0x34
            };*//*

            */
/*{
                    'z', 'g', 'u', '1',
                    'h', 'y', 'n', '1',
                    'e', 'u', '2', '0',
                    'n', 'k', '0', '1'
            };*//*


    uint8_t * output = AES((uint8_t*)plainText);
    print(output);

    delete[] output;
    return 0;
}*/
