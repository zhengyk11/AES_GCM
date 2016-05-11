//
// Created by ZhengYukun on 16/5/11.
//

#ifndef AES_GCM_GCM_H
#define AES_GCM_GCM_H

#include "AES.h"

#define DEBUG 1
#define DEFAULT_IV_LEN 12
#define BLOCK_CIPHER_BLOCK_SIZE 16
#define FIELD_CONST (0xe100000000000000) /* the const value in filed */


uint8_t H[16];
uint8_t T[16][256][16];

#endif //AES_GCM_GCM_H
