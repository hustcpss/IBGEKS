#include "paeks20.h"

static void sha256(const char * string, int len, unsigned char * buf) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, len);
    SHA256_Final(buf, &sha256);
}

int paeks20_setup(pairing_t pairing, element_t g, element_t pk, element_t sk, element_t pk2, element_t sk2) {
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


int paeks20_encrypt(element_t Ca, unsigned char * Cb, pairing_t pairing, element_t g, element_t pk, element_t sk2, const char * w) {
    //加密
    if(w == NULL) {
        return STS_ERR;
    }
    unsigned char gt_data[GT_LEN], g1_data[G1_LEN], cat_data[G1_LEN+24];
    element_t r, tmp1, tmp2, tmp3;
    
    //随机数r
    element_init_Zr(r, pairing);
    element_init_G1(tmp1, pairing);
    element_init_GT(tmp2, pairing);
    element_init_G1(tmp3, pairing);

    element_pow_zn(tmp3, pk, sk2);
    element_to_bytes_compressed(g1_data, tmp3);
    g1_data[G1_LEN-1] = '\0';
    strcpy(cat_data, w);
    strcat(cat_data, g1_data);

    element_from_hash(tmp1, (void*)cat_data, strlen(cat_data));
    
    element_random(r);
    element_pow_zn(Ca, g, r);//Ca = g^r
    element_pow_zn(tmp1, tmp1, r);
    element_pairing(tmp2, tmp1, pk);//Cb = e(H(w, pk^sk2)^r,pk)
    //printf("GT_LEN %d\n", pairing_length_in_bytes_GT(pairing));
    element_to_bytes(gt_data, tmp2);
    gt_data[GT_LEN-1] = '\0';
    //Cb = hash(data);
    sha256(gt_data, GT_LEN, Cb);
    
    element_clear(r);
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(tmp3);
    
    return STS_OK;
}


int paeks20_trapdoor(element_t Tw, pairing_t pairing, element_t sk, element_t pk2, const char * w) {
    //陷门
    if(w == NULL) {
        return STS_ERR;
    }

    unsigned char g1_data[G1_LEN], cat_data[G1_LEN+24];
    element_t tmp1;

    element_init_G1(tmp1, pairing);

    element_pow_zn(tmp1, pk2, sk);
    element_to_bytes_compressed(g1_data, tmp1);
    g1_data[G1_LEN-1] = '\0';
    strcpy(cat_data, w);
    strcat(cat_data, g1_data);

    element_from_hash(Tw, (void*)cat_data, strlen(cat_data));
    element_pow_zn(Tw, Tw, sk);//Tw = H(w)^sk
    
    element_clear(tmp1);

    return STS_OK;
}


int paeks20_test(pairing_t pairing, element_t Tw, element_t A, const unsigned char * B) {
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

