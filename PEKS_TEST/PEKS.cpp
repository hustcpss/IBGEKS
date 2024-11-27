#include "PEKS.h"

PEKS::PEKS() {
    // 初始化pairing
    pairing_init_set_str(pairing, param.c_str());

    // 初始化元素
    element_init_G2(g, pairing);
    element_init_G2(pk, pairing);
    element_init_Zr(sk, pairing);
}

PEKS::~PEKS() {
    // 清理资源
    element_clear(g);
    element_clear(pk);
    element_clear(sk);
    pairing_clear(pairing);
}

int PEKS::setup() {
    // 参数，随机选择一个生成元
    element_random(g);

    // PEKS的私钥，选择一个随机值
    element_random(sk);

    // 计算PEKS的公钥
    element_pow_zn(pk, g, sk);  // pk=g^sk

    return STS_OK;
}


int PEKS::exportkey(unsigned char* pk_s, unsigned char* sk_s){

    element_to_bytes(pk_s, pk);
    element_to_bytes(sk_s, sk);
    
    return STS_OK;
}


int PEKS::importkey(unsigned char* pk_s, unsigned char* sk_s){

    element_from_bytes(pk,pk_s);
    element_from_bytes(sk,sk_s);

    return STS_OK;
}



int PEKS::encrypt(unsigned char* Ca, unsigned char *Cb, const char *w) {
    // 加密
    if (w == nullptr) {
        return STS_ERR;
    }

    unsigned char gt_data[GT_LEN];
    element_t r, tmp1, tmp2,Ca_e;

    // 随机数r
    element_init_Zr(r, pairing);
    element_init_G1(tmp1, pairing);
    element_init_GT(tmp2, pairing);
    element_init_G1(Ca_e, pairing);

    element_from_hash(tmp1, (void *)w, strlen(w));

    element_random(r);
    element_pow_zn(Ca_e, g, r);  // Ca = g^r
    element_pow_zn(tmp1, tmp1, r);
    element_pairing(tmp2, tmp1, pk);  // Cb = e(H(w)^r,pk)

    element_to_bytes(gt_data, tmp2);
    SHA256(gt_data, GT_LEN, Cb);
    element_to_bytes(Ca,Ca_e);

    element_clear(r);
    element_clear(Ca_e);
    element_clear(tmp1);
    element_clear(tmp2);

    return STS_OK;
}

int PEKS::trapdoor(unsigned char* Tw, const char *w) {
    // 陷门
    if (w == nullptr) {
        return STS_ERR;
    }
    element_t Tw_e;
    element_init_G1(Tw_e, pairing);

    element_from_hash(Tw_e, (void *)w, strlen(w));
    element_pow_zn(Tw_e, Tw_e, sk);  // Tw = H(w)^sk

    element_to_bytes(Tw,Tw_e);

    element_clear(Tw_e);

    return STS_OK;
}

int PEKS::test(unsigned char* Tw, unsigned char* A, const unsigned char *B) {
    // 测试密文与陷门
    if (B == nullptr) {
        return STS_ERR;
    }
    element_t tmp,A_e,Tw_e;
    unsigned char gt_data[GT_LEN];
    unsigned char hash_data[HASH_LEN];

    element_init_G1(Tw_e,pairing);
    element_init_G1(A_e,pairing);


    element_from_bytes(A_e,A);
    element_from_bytes(Tw_e,Tw);


    element_init_GT(tmp, pairing);
    element_pairing(tmp, Tw_e, A_e);
    element_to_bytes(gt_data, tmp);
    SHA256(gt_data, GT_LEN, hash_data);

    element_clear(tmp);
    element_clear(Tw_e);
    element_clear(A_e);

    if (memcmp(hash_data, B, HASH_LEN) == 0) {
        return STS_EQU;
    } else {
        return STS_OK;
    }
}