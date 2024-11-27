#include "ibgeks.h"

static void sha256(const char * string, int len, unsigned char * buf) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, len);
    SHA256_Final(buf, &sha256);
}

int ibgeks_setup(pairing_t pairing, element_t sk) {
    //初始化
    //PEKS的私钥，选择一个随机值
    element_init_Zr(sk, pairing);
    element_random(sk);
    
    return STS_OK;
}

int ibgeks_join(pairing_t pairing, const char * ID, element_t sk, element_t gsk) {
    //初始化
    element_t tmp1;

    element_init_G1(tmp1, pairing);
    element_from_hash(tmp1, (void*)ID, strlen(ID));
    element_pow_zn(gsk, tmp1, sk);
    
    element_clear(tmp1);
    return STS_OK;
}


int ibgeks_encrypt(element_t Ca, unsigned char * Cb, pairing_t pairing, element_t gsk, const char * w, const char * ID) {
    //加密
    if(w == NULL) {
        return STS_ERR;
    }

    unsigned char gt_data[GT_LEN];
    element_t r, tmp1, tmp2, tmp3;
    
    //随机数r
    element_init_Zr(r, pairing);
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);
    element_init_GT(tmp3, pairing);

    element_from_hash(tmp1, (void*)ID, strlen(ID));
    element_from_hash(tmp2, (void*)w, strlen(w));
    
    element_random(r);
    element_pow_zn(Ca, tmp1, r);//Ca = H_1(ID)^r
    element_pow_zn(tmp2, tmp2, r);//tmp2 = H_2(w)^r
    element_pairing(tmp3, gsk, tmp2);//tmp3 = e(H_1(ID)^sk,H_2(w)^r)
    //printf("GT_LEN %d\n", pairing_length_in_bytes_GT(pairing));
    element_to_bytes(gt_data, tmp3);
    //Cb = hash(data);
    sha256(gt_data, GT_LEN, Cb);//Cb = H_3(e(H_1(ID)^sk,H_2(w)^r))
    
    element_clear(r);
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(tmp3);
    
    return STS_OK;
}


int ibgeks_trapdoor(element_t Tw, element_t sk, const char * w) {

    if(w == NULL) {
        return STS_ERR;
    }

    element_from_hash(Tw, (void*)w, strlen(w));
    element_pow_zn(Tw, Tw, sk);//Tw = H_2(w)^sk

    return STS_OK;
}


int ibgeks_test(pairing_t pairing, element_t Tw, element_t A, const unsigned char * B) {

    if(B == NULL) {
        return STS_ERR;
    }
    element_t tmp;
    unsigned char gt_data[GT_LEN];
    unsigned char hash_data[HASH_LEN];

    element_init_GT(tmp, pairing);
    //hash_data = hash(e(Tw,Ca));
    element_pairing(tmp, Tw, A);
    element_to_bytes(gt_data, tmp);
    sha256(gt_data, GT_LEN, hash_data);
    
    element_clear(tmp);
    
    if(memcmp(hash_data, B, HASH_LEN) == 0) {
        return STS_EQU;
    } else {
        return STS_OK;
    }
}

