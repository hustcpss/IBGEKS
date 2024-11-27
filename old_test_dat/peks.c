#include "peks.h"

static void sha256(const char * string, int len, unsigned char * buf) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, len);
    SHA256_Final(buf, &sha256);
}

int peks_setup(pairing_t pairing, element_t g, element_t pk, element_t sk) {
    //初始化
        
    //参数，随机选择一个生成元
    element_init_G2(g, pairing);
    element_random(g);
    //PEKS的私钥，选择一个随机值
    element_init_Zr(sk, pairing);
    element_random(sk);
    //计算PEKS的公钥
    element_init_G2(pk, pairing);
    element_pow_zn(pk, g, sk);//pk=g^sk
    
    return STS_OK;
}


int peks_encrypt(element_t Ca, unsigned char * Cb, pairing_t pairing, element_t g, element_t pk, const char * w) {
    //加密
    if(w == NULL) {
        return STS_ERR;
    }

    unsigned char gt_data[GT_LEN];
    element_t r, tmp1, tmp2;
    
    //随机数r
    element_init_Zr(r, pairing);
    element_init_G1(tmp1, pairing);
    element_init_GT(tmp2, pairing);

    element_from_hash(tmp1, (void*)w, strlen(w));
    
    element_random(r);
    element_pow_zn(Ca, g, r);//Ca = g^r
    element_pow_zn(tmp1, tmp1, r);
    element_pairing(tmp2, tmp1, pk);//Cb = e(H(w)^r,pk)
    //printf("GT_LEN %d\n", pairing_length_in_bytes_GT(pairing));
    element_to_bytes(gt_data, tmp2);
    //Cb = hash(data);
    sha256(gt_data, GT_LEN, Cb);
    
    element_clear(r);
    element_clear(tmp1);
    element_clear(tmp2);
    
    return STS_OK;
}


int peks_trapdoor(element_t Tw, element_t sk, const char * w) {
    //陷门
    if(w == NULL) {
        return STS_ERR;
    }

    element_from_hash(Tw, (void*)w, strlen(w));
    element_pow_zn(Tw, Tw, sk);//Tw = H(w)^sk

    return STS_OK;
}


int peks_test(pairing_t pairing, element_t Tw, element_t A, const unsigned char * B) {
    //测试密文与陷门
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

