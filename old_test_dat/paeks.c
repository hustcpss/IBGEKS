#include "paeks.h"

static void sha256(const char * string, int len, unsigned char * buf) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, len);
    SHA256_Final(buf, &sha256);
}

int paeks_setup(pairing_t pairing, element_t g, element_t pk, element_t sk, element_t pk2, element_t sk2) {
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

    element_init_Zr(sk2, pairing);
    element_random(sk2);
    //计算PEKS的公钥
    element_init_G2(pk2, pairing);
    element_pow_zn(pk2, g, sk2);//pk=g^sk
    
    return STS_OK;
}


int paeks_encrypt(element_t Ca, element_t Cb2, pairing_t pairing, element_t g, element_t pk, element_t sk2, const char * w) {
    //加密
    if(w == NULL) {
        return STS_ERR;
    }
    element_t r, tmp1, tmp2;
    
    //随机数r
    element_init_Zr(r, pairing);
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);

    element_from_hash(tmp1, (void*)w, strlen(w));
    
    element_random(r);
    element_pow_zn(tmp1, tmp1, sk2);
    element_pow_zn(tmp2, g, r);
    element_mul(Ca, tmp1, tmp2);//Ca = H_1(w)^sks * g^r
    element_pow_zn(Cb2, pk, r);//Cb = pk^r
    
    element_clear(r);
    element_clear(tmp1);
    element_clear(tmp2);
    
    return STS_OK;
}


int paeks_trapdoor(element_t Tw2, pairing_t pairing, element_t sk, element_t pk2, const char * w) {
    //陷门
    if(w == NULL) {
        return STS_ERR;
    }

    element_t tmp1;

    element_init_G1(tmp1, pairing);
    element_from_hash(tmp1, (void*)w, strlen(w));
    
    element_pow_zn(tmp1, tmp1, sk);
    element_pairing(Tw2, tmp1, pk2);//Cb = e(H(w)^sk,pk2)
    
    element_clear(tmp1);

    return STS_OK;
}


int paeks_test(pairing_t pairing, element_t Tw2, element_t A, element_t B, element_t g, element_t pk) {
    //测试密文与陷门
    if(B == NULL) {
        return STS_ERR;
    }
    element_t tmp1, tmp2, tmp3;
    unsigned char gt_data[GT_LEN];
    unsigned char hash_data[HASH_LEN];

    element_init_GT(tmp1, pairing);
    element_pairing(tmp1, B, g);
    element_init_GT(tmp2, pairing);
    element_mul(tmp2, Tw2, tmp1);//tmp2 = Tw * e(C2, g)

    element_init_GT(tmp3, pairing);
    element_pairing(tmp3, A, pk);//tmp3 = e(C1, pk)
    
    element_clear(tmp1);
    
    if(element_cmp(tmp2, tmp3) == 0) {
        element_clear(tmp2);
        element_clear(tmp3);
        return STS_EQU;
    } else {
        element_clear(tmp2);
        element_clear(tmp3);
        return STS_OK;
    }
}

