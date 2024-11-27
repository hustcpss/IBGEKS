#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pbc/pbc.h>
#include <openssl/sha.h>


//peks名称可修改
#define STS_OK 0
#define STS_EQU 1
#define STS_ERR 2
#define GT_LEN 384
#define HASH_LEN 32

int ibgeks_setup(pairing_t pairing, element_t sk);

int ibgeks_join(pairing_t pairing, const char * ID, element_t sk, element_t gsk);

int ibgeks_encrypt(element_t Ca, unsigned char * Cb, pairing_t pairing, element_t gsk, const char * w, const char * ID);

int ibgeks_trapdoor(element_t Tw, element_t sk, const char * w);

int ibgeks_test(pairing_t pairing, element_t Tw, element_t A, const unsigned char * B);

