#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "/usr/local/include/pbc/pbc.h"
#include <openssl/sha.h>


//peks名称可修改
#define STS_OK 0
#define STS_EQU 1
#define STS_ERR 2
#define GT_LEN 384
#define HASH_LEN 32

int peks_setup(pairing_t pairing, element_t g, element_t pk, element_t sk);
//初始化

int peks_encrypt(element_t Ca, unsigned char * Cb, pairing_t pairing, element_t g, element_t pk, const char * w);
//工作量延迟加密

int peks_trapdoor(element_t Tw, element_t sk, const char * w);
//可验证工作量的陷门

int peks_test(pairing_t pairing, element_t Tw, element_t A, const unsigned char * B);
//测试密文与陷门
