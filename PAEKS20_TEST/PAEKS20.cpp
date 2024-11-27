#include "PAEKS20.h"
#include <cstring>
#include <openssl/sha.h>

PAEKS20::PAEKS20() {
    // 初始化Pairing
    pairing_init_set_str(pairing, param.c_str());

    // 调用Setup函数
    setup();
}

PAEKS20::~PAEKS20() {
    // 清理Pairing和元素
    element_clear(g);
    element_clear(pk);
    element_clear(sk);
    element_clear(pk2);
    element_clear(sk2);
    pairing_clear(pairing);
}

void PAEKS20::setup() {
    // 初始化元素
    element_init_G2(g, pairing);
    element_init_G2(pk, pairing);
    element_init_Zr(sk, pairing);
    element_init_G2(pk2, pairing);
    element_init_Zr(sk2, pairing);

    // 生成随机元素
    element_random(g);
    element_random(sk);
    element_random(sk2);

    // 计算公钥
    element_pow_zn(pk, g, sk);
    element_pow_zn(pk2, g, sk2);
}

int PAEKS20::encrypt(unsigned char* Ca, unsigned char * Cb, const std::string w) {
    // 加密

    unsigned char gt_data[GT_LEN], g1_data[G1_LEN] = {0}, cat_data[G1_LEN+HASH_LEN] = {0};
    unsigned char w_h[HASH_LEN];
    element_t r, tmp1, tmp2, tmp3;
    element_t Ca_e;

    // 初始化元素
    element_init_Zr(r, pairing);
    element_init_G1(tmp1, pairing);
    element_init_GT(tmp2, pairing);
    element_init_G1(tmp3, pairing);
    element_init_G1(Ca_e, pairing);

    // 计算临时值
    element_pow_zn(tmp3, pk, sk2);
    element_to_bytes(g1_data, tmp3);
    SHA256((unsigned char*)w.c_str(),w.length(),cat_data);
    strncpy((char*)cat_data+HASH_LEN, (char*)g1_data, G1_LEN);

    element_from_hash(tmp1, (void *)cat_data, G1_LEN+HASH_LEN);

    // 生成随机数r
    element_random(r);
    element_pow_zn(Ca_e, g, r);
    element_pow_zn(tmp1, tmp1, r);
    element_pairing(tmp2, tmp1, pk);

    // 转换成字节数组并哈希
    element_to_bytes(gt_data, tmp2);
    SHA256(gt_data, GT_LEN, Cb);

    element_to_bytes(Ca,Ca_e);

    // 清理元素
    element_clear(r);
    element_clear(Ca_e);
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(tmp3);

    return STS_OK;
}

int PAEKS20::trapdoor(unsigned char* Tw, const std::string w) {
    // 陷门

    unsigned char g1_data[G1_LEN]={0}, cat_data[G1_LEN+HASH_LEN]={0};
    element_t tmp1,Tw_e;

    // 初始化元素
    element_init_G1(Tw_e,pairing);
    element_init_G1(tmp1, pairing);

    // 计算临时值
    element_pow_zn(tmp1, pk2, sk);
    element_to_bytes(g1_data, tmp1);
    SHA256((unsigned char*)w.c_str(),w.length(),cat_data);
    strncpy((char*)cat_data+HASH_LEN, (char*)g1_data, G1_LEN);

    element_from_hash(Tw_e, (void*)cat_data, G1_LEN+HASH_LEN);
    element_pow_zn(Tw_e, Tw_e, sk);
    
    element_to_bytes(Tw,Tw_e);

    // 清理元素
    element_clear(Tw_e);
    element_clear(tmp1);

    return STS_OK;
}

int PAEKS20::test(unsigned char* Tw, unsigned char* A, const unsigned char * B) {
    // 测试密文与陷门
    if (B == nullptr) {
        return STS_ERR;
    }

    element_t tmp,Tw_e,A_e;
    unsigned char gt_data[GT_LEN];
    unsigned char hash_data[HASH_LEN];

    // 初始化元素
    element_init_GT(tmp, pairing);
    element_init_G1(Tw_e, pairing);
    element_init_G1(A_e,pairing);

    element_from_bytes(Tw_e,Tw);
    element_from_bytes(A_e, A);

    // 计算哈希值
    element_pairing(tmp, Tw_e, A_e);
    element_to_bytes(gt_data, tmp);
    SHA256(gt_data, GT_LEN, hash_data);

    // 清理元素
    element_clear(tmp);
    element_clear(A_e);
    element_clear(Tw_e);

    if (memcmp(hash_data, B, HASH_LEN) == 0) {
        return STS_EQU;
    } else {
        return STS_OK;
    }
}


int PAEKS20::exportkey(unsigned char* pk_s, unsigned char* sk_s) {

    element_to_bytes(pk_s, pk);
    element_to_bytes(sk_s, sk);
    
    return STS_OK;
}


int PAEKS20::importkey(unsigned char* pk_s, unsigned char* sk_s){

    element_from_bytes(pk,pk_s);
    element_from_bytes(sk,sk_s);

    return STS_OK;
}
