#include "GCM.h"


#if defined(DEBUG)
static int countY = 0;
#endif

void printf_output(uint8_t *p, size_t length) {
    uint8_t i = 0, j = 0;
    if ( length > BLOCK_CIPHER_BLOCK_SIZE) {
        // first block
        for ( i = 0; i < BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
            printf("%2x ", p[i]);
        }
        printf("\n");
        // middle blocks
        for ( i = 1; i < length/BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
            printf("                ");
            for ( j = 0; j < BLOCK_CIPHER_BLOCK_SIZE; j++ ) {
                printf("%2x ", p[i*BLOCK_CIPHER_BLOCK_SIZE+j]);
            }
            printf("\n");
        }
        // last block
        printf("                ");
        i = length/BLOCK_CIPHER_BLOCK_SIZE*BLOCK_CIPHER_BLOCK_SIZE;
        for ( ; i < length; i++ ) {
            printf("%2x ", p[i]);
        }
        printf("\n");
    } else {
        for ( i = 0; i < length; i++ ) {
            printf("%2x ", p[i]);
        }
        printf("\n");
    }
}

static void incr (uint8_t *iv) {
    iv += 12;
    uint32_t temp = ((uint32_t)iv[0]<<24) + ((uint32_t)iv[1]<<16) + ((uint32_t)iv[2]<<8) + ((uint32_t)iv[3]) + 1;
    iv[3] = (uint8_t)(temp); // the priority of () is higher than >>, ^_^
    iv[2] = (uint8_t)(temp>>8);
    iv[1] = (uint8_t)(temp>>16);
    iv[0] = (uint8_t)(temp>>24);
}

void multi(uint8_t T[][256][16], uint8_t *output) {
    uint8_t i, j;
    uint8_t temp[16];
    for ( i = 0; i < 16; i++ ) {
        temp[i] = output[i];
        output[i] = 0;
    }
    for ( i = 0; i < 16; i++ ) {
        for ( j = 0; j < 16; j++ ) {
            output[j] ^= T[i][*(temp+i)][j];
        }
    }
}

void ghash(uint8_t T[][256][16],
           const uint8_t *add,
           size_t add_len,
           const uint8_t *cipher,
           size_t length,
           uint8_t *output) {
    /* x0 = 0 */
    *(uint64_t *)output = 0;
    *((uint64_t *)output+1) = 0;

    /* compute with add */
    int i = 0, j = 0;
    for ( i = 0; i < add_len/BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
        *(uint64_t *)output ^= *(uint64_t *)add;
        *((uint64_t *)output+1) ^= *((uint64_t *)add+1);
        add += BLOCK_CIPHER_BLOCK_SIZE;
        multi(T, output);
    }

    if ( add_len % BLOCK_CIPHER_BLOCK_SIZE ) {
        // the remaining add
        for ( i = 0; i < add_len%BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
            *(output+i) ^= *(add+i);
        }
        multi(T, output);
    }

    /* compute with cipher text */
    for ( i = 0; i < length/BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
        *(uint64_t *)output ^= *(uint64_t *)cipher;
        *((uint64_t *)output+1) ^= *((uint64_t *)cipher+1);
        cipher += BLOCK_CIPHER_BLOCK_SIZE;
        multi(T, output);
    }
    if ( length % BLOCK_CIPHER_BLOCK_SIZE ) {
        // the remaining cipher
        for ( i = 0; i < length%BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
            *(output+i) ^= *(cipher+i);
        }
        multi(T, output);
    }

    /* eor (len(A)||len(C)) */
    uint64_t temp_len = (uint64_t)(add_len*8); // len(A) = (uint64_t)(add_len*8)
    for ( i = 1; i <= BLOCK_CIPHER_BLOCK_SIZE/2; i++ ) {
        output[BLOCK_CIPHER_BLOCK_SIZE/2-i] ^= (uint8_t)temp_len;
        temp_len = temp_len >> 8;
    }
    temp_len = (uint64_t)(length*8); // len(C) = (uint64_t)(length*8)
    for ( i = 1; i <= BLOCK_CIPHER_BLOCK_SIZE/2; i++ ) {
        output[BLOCK_CIPHER_BLOCK_SIZE-i] ^= (uint8_t)temp_len;
        temp_len = temp_len >> 8;
    }
    multi(T, output);
}

void otherT(uint8_t T[][256][16]) {
    int i = 0, j = 0, k = 0;
    uint64_t vh, vl;
    uint64_t zh, zl;
    for ( i = 0; i < 256; i++ ) {
        vh = ((uint64_t)T[0][i][0]<<56) ^ ((uint64_t)T[0][i][1]<<48) ^ ((uint64_t)T[0][i][2]<<40) ^ ((uint64_t)T[0][i][3]<<32) ^
             ((uint64_t)T[0][i][4]<<24) ^ ((uint64_t)T[0][i][5]<<16) ^ ((uint64_t)T[0][i][6]<<8) ^ ((uint64_t)T[0][i][7]);
        vl = ((uint64_t)T[0][i][8]<<56) ^ ((uint64_t)T[0][i][9]<<48) ^ ((uint64_t)T[0][i][10]<<40) ^ ((uint64_t)T[0][i][11]<<32) ^
             ((uint64_t)T[0][i][12]<<24) ^ ((uint64_t)T[0][i][13]<<16) ^ ((uint64_t)T[0][i][14]<<8) ^ ((uint64_t)T[0][i][15]);
        zh = zl = 0;
        for ( j = 0; j <= 120; j++ ) {
            if ( (j > 0) && (0 == j%8) ) {
                zh ^= vh;
                zl ^= vl;
                for ( k = 1; k <= BLOCK_CIPHER_BLOCK_SIZE/2; k++ ) {
                    T[j/8][i][BLOCK_CIPHER_BLOCK_SIZE/2-k] = (uint8_t)zh;
                    zh = zh >> 8;
                    T[j/8][i][BLOCK_CIPHER_BLOCK_SIZE-k] = (uint8_t)zl;
                    zl = zl >> 8;
                }
                zh = zl = 0;
            }
            if ( vl & 0x1 ) {
                vl = vl >> 1;
                if ( vh & 0x1) { vl ^= 0x8000000000000000;}
                vh = vh >> 1;
                vh ^= FIELD_CONST;
            } else {
                vl = vl >> 1;
                if ( vh & 0x1) { vl ^= 0x8000000000000000;}
                vh = vh >> 1;
            }
        }
    }
}

void computeTable (uint8_t T[][256][16], uint8_t H[]) {

    // zh is the higher 64-bit, zl is the lower 64-bit
    uint64_t zh = 0, zl = 0;
    // vh is the higher 64-bit, vl is the lower 64-bit
    uint64_t vh = ((uint64_t)H[0]<<56) ^ ((uint64_t)H[1]<<48) ^ ((uint64_t)H[2]<<40) ^ ((uint64_t)H[3]<<32) ^
                  ((uint64_t)H[4]<<24) ^ ((uint64_t)H[5]<<16) ^ ((uint64_t)H[6]<<8) ^ ((uint64_t)H[7]);
    uint64_t vl = ((uint64_t)H[8]<<56) ^ ((uint64_t)H[9]<<48) ^ ((uint64_t)H[10]<<40) ^ ((uint64_t)H[11]<<32) ^
                  ((uint64_t)H[12]<<24) ^ ((uint64_t)H[13]<<16) ^ ((uint64_t)H[14]<<8) ^ ((uint64_t)H[15]);
    uint8_t temph;

    uint64_t tempvh = vh;
    uint64_t tempvl = vl;
    int i = 0, j = 0;
    for ( i = 0; i < 256; i++ ) {
        temph = (uint8_t)i;
        vh = tempvh;
        vl = tempvl;
        zh = zl = 0;

        for ( j = 0; j < 8; j++ ) {
            if ( 0x80 & temph ) {
                zh ^= vh;
                zl ^= vl;
            }
            if ( vl & 0x1 ) {
                vl = vl >> 1;
                if ( vh & 0x1) { vl ^= 0x8000000000000000;}
                vh = vh >> 1;
                vh ^= FIELD_CONST;
            } else {
                vl = vl >> 1;
                if ( vh & 0x1) { vl ^= 0x8000000000000000;}
                vh = vh >> 1;
            }
            temph = temph << 1;
        }
        // get result
        for ( j = 1; j <= BLOCK_CIPHER_BLOCK_SIZE/2; j++ ) {
            T[0][i][BLOCK_CIPHER_BLOCK_SIZE/2-j] = (uint8_t)zh;
            zh = zh >> 8;
            T[0][i][BLOCK_CIPHER_BLOCK_SIZE-j] = (uint8_t)zl;
            zl = zl >> 8;
        }
    }
    otherT(T);
}

int GCM_crypt_and_tag(const unsigned char *iv,
                      size_t iv_len,
                      const unsigned char *add,
                      size_t add_len,
                      const unsigned char *input,
                      size_t length,
                      unsigned char *tag,
                      size_t tag_len,
                      unsigned char *output) {

    if ( tag_len <= 0 || tag_len > BLOCK_CIPHER_BLOCK_SIZE ) {
        return -1;
    }

    uint8_t y0[BLOCK_CIPHER_BLOCK_SIZE] = {0}; // store the counter
    /* set H */
    uint8_t * ency0 = AES(y0);

    int i = 0;
    for ( i = 0; i < BLOCK_CIPHER_BLOCK_SIZE; i++ ) { H[i] = ency0[i]; }

#if defined(DEBUG)
    printf("\n----AUTH-ENCRYPTION----\n");
    printf("COMPUTE TABLES\n");
#endif

    computeTable(T, H);

#if defined(DEBUG)
    printf("H:              ");
    printf_output(H, BLOCK_CIPHER_BLOCK_SIZE);
#endif

    /* compute y0 (initilization vector) */
    if (DEFAULT_IV_LEN == iv_len) {
        *(uint32_t*)y0 = *(uint32_t*)iv;
        *((uint32_t*)y0+1) = *((uint32_t*)iv+1);
        *((uint32_t*)y0+2) = *((uint32_t*)iv+2);
        y0[15] = 1;
    } else {
        ghash(T, NULL, 0, (const uint8_t*)iv, iv_len, y0);
    }


#if defined(DEBUG)
    printf("Y%d:             ", countY);
    printf_output(y0, BLOCK_CIPHER_BLOCK_SIZE);
#endif

    /* compute ency0 = ENC(K, y0) */
    delete[] ency0;
    ency0 = AES(y0);
    //(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, ency0);

#if defined(DEBUG)
    printf("E(K, Y%d):       ", countY++);
    printf_output(ency0, BLOCK_CIPHER_BLOCK_SIZE);
#endif

    /* encyrption */
    uint8_t * output_temp = output; // store the start pointer of cipher text
    for ( i = 0; i < length/BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
        incr(y0);

#if defined(DEBUG)
        printf("Y%d:             ", countY);
        printf_output(y0, BLOCK_CIPHER_BLOCK_SIZE);
#endif
        //(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, output);
        uint8_t * tmp = AES(y0);
        for(int j = 0;j < 16;j++){
            output[j] = tmp[j];
        }
        delete[] tmp;

#if defined(DEBUG)
        printf("E(K, Y%d):       ", countY++);
        printf_output(output, BLOCK_CIPHER_BLOCK_SIZE);
#endif

        *(uint64_t*)output ^= *(uint64_t*)input;
        *((uint64_t*)output+1) ^= *((uint64_t*)input+1);
        output += BLOCK_CIPHER_BLOCK_SIZE;
        input += BLOCK_CIPHER_BLOCK_SIZE;
    }

    // the remaining plain text
    if ( length % BLOCK_CIPHER_BLOCK_SIZE ) {
        incr(y0);

#if defined(DEBUG)
        printf("Y%d:             ", countY);
        printf_output(y0, BLOCK_CIPHER_BLOCK_SIZE);
#endif

        //(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, y0);
        uint8_t * tmp = AES(y0);
        for(int j = 0;j < 16;j++){
            y0[j] = tmp[j];
        }
        delete[] tmp;

#if defined(DEBUG)
        printf("E(K, Y%d):       ", countY++);
        printf_output(y0, BLOCK_CIPHER_BLOCK_SIZE);
#endif

        for ( i = 0; i < length%BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
            *(output+i) = *(input+i) ^ *(y0+i);
        }
    }

#if defined(DEBUG)
    printf("CIPHER:         ");
    printf_output(output_temp, length);
#endif

    /* compute tag, y0 is useless now */
    ghash(T, add, add_len, (const uint8_t*)output_temp, length, y0);
#if defined(DEBUG)
    printf("GHASH(H, A, C): ");
    printf_output(y0, BLOCK_CIPHER_BLOCK_SIZE);
#endif

    for ( i = 0; i < tag_len; i++ ) {
        tag[i] = y0[i] ^ ency0[i];
    }

#if defined(DEBUG)
    printf("TAG:            ");
    printf_output(tag, tag_len);
#endif

    delete[] ency0;
    return 0;
}



int main(){

    const uint8_t cipherKey_str[] = {
            0x3A, 0xE1, 0x15, 0x62,
            0xA8, 0xF3, 0xC7, 0x1A,
            0x2B, 0xF6, 0xDF, 0xA1,
            0x50, 0x9B, 0xCA, 0xF1 //题目
    };
    //"3AE11562A8F3C71A2BF6DFA1509BCAF1";     //密钥
            /*{ //样例密钥
                    0x2b, 0x28, 0xab, 0x09,
                    0x7e, 0xae, 0xf7, 0xcf,
                    0x15, 0xd2, 0x15, 0x4f,
                    0x16, 0xa6, 0x88, 0x3c
            };*/
    /*{
            0x3A, 0xA8, 0x2B, 0x50,
            0xE1, 0xF3, 0xF6, 0x9B,
            0x15, 0xC7, 0xDF, 0xCA,
            0x62, 0x1A, 0xA1, 0xF1
    };*/

    uint8_t cipherKey[16];
    for(int i=0;i<16;i++){
        cipherKey[i] = cipherKey_str[i%4 * 4 + i/4];
    }

    //const uint8_t plainText[] = "zhengyukun201101";                 //明文
            /*{ //样例明文
                    0x32, 0x88, 0x31, 0xe0,
                    0x43, 0x5a, 0x31, 0x37,
                    0xf6, 0x30, 0x98, 0x07,
                    0xa8, 0x8d, 0xa2, 0x34
            };*/
    /*{
            'z', 'g', 'u', '1',
            'h', 'y', 'n', '1',
            'e', 'u', '2', '0',
            'n', 'k', '0', '1'
    };*/

    size_t length = 20;
    /*uint8_t input[BLOCK_CIPHER_BLOCK_SIZE*3+DEFAULT_IV_LEN] = {
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
            0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
            0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
            0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};*/
    uint8_t input[] = {
            'z', 'h', 'e', 'n', 'g', 'y', 'u', 'k', 'u', 'n', '2', '0', '1', '1', '0', '1', '1', '3', '8', '4'};
    /*,'z', 'h', 'e', 'n', 'g', 'y', 'u', 'k', 'u', 'n', '2', '0', '1', '1', '0', '1', '1', '3', '8', '4',
    'z', 'h', 'e', 'n', 'g', 'y', 'u', 'k', 'u', 'n', '2', '0', '1', '1', '0', '1', '1', '3', '8', '4'};*/
    uint8_t output[20];//[BLOCK_CIPHER_BLOCK_SIZE*3+DEFAULT_IV_LEN];
    size_t add_len = BLOCK_CIPHER_BLOCK_SIZE+4;
    uint8_t add[BLOCK_CIPHER_BLOCK_SIZE+4] = {
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
            0xab, 0xad, 0xda, 0xd2};
    size_t iv_len = 4*BLOCK_CIPHER_BLOCK_SIZE-4;
    uint8_t iv[4*BLOCK_CIPHER_BLOCK_SIZE-4] = {
            0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5, 0x55, 0x90, 0x9c, 0x5a, 0xff, 0x52, 0x69, 0xaa,
            0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d, 0xa1, 0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28,
            0xc3, 0xc0, 0xc9, 0x51, 0x56, 0x80, 0x95, 0x39, 0xfc, 0xf0, 0xe2, 0x42, 0x9a, 0x6b, 0x52, 0x54,
            0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57, 0xa6, 0x37, 0xb3, 0x9b};

    uint8_t tag[16] = {0};
    size_t tag_len = 16;

    keySchedule(cipherKey);
    //uint8_t * output;
    /*uint8_t * output = AES((uint8_t*)plainText);
    print(output);
*/

    /*for(int i = 0;i<16;i++){
        if(i % 4 == 0)
            printf("\n");
        printf("0x%x, ", cipherKey[i]);
    }
    printf("\n");*/


    //delete[] output;

    GCM_crypt_and_tag((const unsigned char *)iv,
                      iv_len,
                      (const unsigned char *)add,
                      add_len,
                      (const unsigned char *)input,
                      length,
                      (unsigned char *)tag,
                      tag_len,
                      output);

    return 0;
}