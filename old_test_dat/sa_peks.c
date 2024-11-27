#include "sa_peks.h"

static void sha256(const char * string, int len, unsigned char * buf) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, len);
    SHA256_Final(buf, &sha256);
}

static int hash_to_zn(mpz_t hash, const char * w) {
    //将关键字映射到Z_n
    const char * pass = "0123456789ABCDEF";
    unsigned char hw_str[HASH_LEN];
    char mpz_str[2*HASH_LEN + 2];

    sha256(w, strlen(w), hw_str);

    //哈希结果转换为十六进制的字符串
    for(int i = 0, j = 0; i < HASH_LEN; i++, j++) {
        mpz_str[j] = pass[ hw_str[i] & 0xf ];
        hw_str[i] >>= 4;
        j++;
        mpz_str[j] = pass[ hw_str[i] & 0xf ];
    }
    mpz_str[2*HASH_LEN] = '\0';
    mpz_set_str(hash, mpz_str, 16);

    return STS_OK;
}

static int hash_to_group(mpz_t A, element_t B, const char * w) {
    //从Z_n映射到G1群
    char buf[512];
    int len;
    len = gmp_snprintf(buf, 256, "%Zx", A);
    if(len > 256) {//需要考虑N的位数，应该是P，Q的2倍
        len = 256;
    }
    strcpy(buf + 256, w);
    element_from_hash(B, buf, len + strlen(w));
    //element_printf("%B\n", B);

    return STS_OK;
}

int rsa_setup(int lambda, mpz_t N, mpz_t e, mpz_t d) {
    //初始化Z_n*的部分

    gmp_randstate_t rndst;
    mpz_t p, q, phi_N;

    mpz_init(p);
    mpz_init(q);
    mpz_init(phi_N);
    //随机数发生装置
    gmp_randinit_default(rndst);
    gmp_randseed_ui(rndst, (unsigned long int)time(NULL));

    //选择两个大素数p,q，计算N=pq
    mpz_urandomb(p, rndst, lambda);
    if(mpz_even_p(p)) {
        mpz_add_ui(p, p ,1);
    }
    while(mpz_probab_prime_p(p, REPS) == 0) {
        mpz_add_ui(p, p, 2);
    }
    
    if(mpz_even_p(q)) {
        mpz_add_ui(q, q ,1);
    }
    while(mpz_probab_prime_p(q, REPS) == 0) {
        mpz_add_ui(q, q, 2);
    }
    mpz_mul(N, p, q);//N=pq

    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi_N, p, q);//phi_N=(p-1)(q-1)

    mpz_urandomb(e, rndst, lambda);//随机选择一个RSA公钥e>N
    while(mpz_cmp(N, e) > 0) {
        mpz_urandomb(e, rndst, lambda);
    }

    while(mpz_invert(d, e, phi_N) == 0) {//是否存在合法的RSA私钥d
        mpz_urandomb(e, rndst, lambda);//随机选择一个RSA公钥e>N
        while(mpz_cmp(N, e) > 0) {
            mpz_urandomb(e, rndst, lambda);
        }
    }
    gmp_randclear(rndst);
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(phi_N);
    return STS_OK;
}

static int ks_derived(mpz_t ksw, mpz_t N, mpz_t e, mpz_t d, const char * w) {
    //与KS交互获取关键字信息的过程
    mpz_t r, hw;
    gmp_randstate_t rndst;

    mpz_init(r);
    mpz_init(hw);
    gmp_randinit_default(rndst);

    hash_to_zn(ksw, w);
    mpz_urandomm(r, rndst, N);
    mpz_powm(hw, r, e, N);//w1=r^e x H(w) mod N
    mpz_mul(ksw, hw, ksw);
    mpz_mod(hw, ksw, N);

    mpz_powm(ksw, hw, d, N);//w2=w1^d mod N

    mpz_invert(hw, r, N);//w3=r^-1 x w2 mod N
    mpz_mul(ksw, hw, ksw);
    mpz_mod(ksw, ksw, N);

    mpz_clear(r);
    mpz_clear(hw);
    gmp_randclear(rndst);
    return STS_OK;
}

int sa_peks_setup(pairing_t pairing, element_t g, element_t pk, element_t sk) {
    //初始化
        
    //参数，随机选择一个生成元
    element_init_G1(g, pairing);
    element_random(g);
    //PEKS的私钥，选择一个随机值
    element_init_Zr(sk, pairing);
    element_random(sk);
    //计算PEKS的公钥
    element_init_G1(pk, pairing);
    element_pow_zn(pk, g, sk);//pk=g^sk
    
    return STS_OK;
}


int sa_peks_encrypt(element_t Ca, unsigned char * Cb, pairing_t pairing, element_t g, element_t pk, mpz_t N, mpz_t e, mpz_t d, const char * w) {
    //工作量延迟加密
    if(w == NULL) {
        return STS_ERR;
    }

    unsigned char gt_data[GT_LEN];
    element_t r, tmp1, tmp2;
    mpz_t Delt;
    //随机数r
    element_init_Zr(r, pairing);
    element_init_G1(tmp1, pairing);
    element_init_GT(tmp2, pairing);
    mpz_init(Delt);


    ks_derived(Delt, N, e, d, w);

    hash_to_group(Delt, tmp1, w);

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
    mpz_clear(Delt);
    return STS_OK;
}


int sa_peks_trapdoor(element_t Tw, element_t sk, mpz_t N, mpz_t e, mpz_t d, const char * w) {
    //可验证工作量的陷门
    if(w == NULL) {
        return STS_ERR;
    }
    mpz_t delt;
    
    mpz_init(delt);
    
    ks_derived(delt, N, e, d, w);

    hash_to_group(delt, Tw, w);

    element_pow_zn(Tw, Tw, sk);//Tw = H(w)^sk

    mpz_clear(delt);
    return STS_OK;
}


int sa_peks_test(pairing_t pairing, element_t Tw, element_t A, const unsigned char * B) {
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

