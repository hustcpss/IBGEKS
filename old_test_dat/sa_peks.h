#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pbc/pbc.h>
#include <openssl/sha.h>


//sa_peks名称可修改
#define STS_OK 0
#define STS_EQU 1
#define STS_ERR 2
#define GT_LEN 128//?
#define HASH_LEN 32
#define REPS 20//Miller-Rabin素性判别的次数

static int hash_keyword(mpz_t hash, const char * w);
//关键字哈希转为模N剩余类环

static int ks_derived(mpz_t ksw, mpz_t N, mpz_t e, mpz_t d, const char * w);

int rsa_setup(int lambda, mpz_t N, mpz_t e, mpz_t d);
//初始化摸N剩余类环的部分

int sa_peks_setup(pairing_t pairing, element_t g, element_t pk, element_t sk);
//初始化

int sa_peks_encrypt(element_t Ca, unsigned char * Cb, pairing_t pairing, element_t g, element_t pk, mpz_t N, mpz_t e, mpz_t d, const char * w);
//加密

int sa_peks_trapdoor(element_t Tw, element_t sk, mpz_t N, mpz_t e, mpz_t d, const char * w);
//陷门

int sa_peks_test(pairing_t pairing, element_t Tw, element_t A, const unsigned char * B);
//测试密文与陷门
