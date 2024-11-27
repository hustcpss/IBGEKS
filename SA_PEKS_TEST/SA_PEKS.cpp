#include "SA_PEKS.h"

SAPeks::SAPeks() {
    SAPeks::setup();
    SAPeks::rsaSetup(1024);
}

SAPeks::~SAPeks() {

    element_clear(g);
    element_clear(sk);
    element_clear(pk);
    mpz_clear(N);
    mpz_clear(e);
    mpz_clear(d);
    pairing_clear(pairing);
}


int SAPeks::hashToZn(mpz_t hash, const std::string w) {
    const char *pass = "0123456789ABCDEF";
    unsigned char hw_str[HASH_LEN];
    char mpz_str[2 * HASH_LEN + 2];

    SHA256((unsigned char*) w.c_str(), w.length(), hw_str);

    for (int i = 0, j = 0; i < HASH_LEN; i++, j++) {
        mpz_str[j] = pass[hw_str[i] & 0xf];
        hw_str[i] >>= 4;
        j++;
        mpz_str[j] = pass[hw_str[i] & 0xf];
    }
    mpz_str[2 * HASH_LEN] = '\0';
    mpz_set_str(hash, mpz_str, 16);

    return STS_OK;
}

int SAPeks::hashToGroup(mpz_t A, element_t B, const std::string w) {
    char buf[512];
    int len;
    len = gmp_snprintf(buf, 256, "%Zx", A);
    if (len > 256) {
        len = 256;
    }
    strcpy(buf + 256, w.c_str());
    element_from_hash(B, buf, len + w.length());

    return STS_OK;
}

int SAPeks::ksDerived(mpz_t ksw, const std::string w) {
    mpz_t r, hw;
    gmp_randstate_t rndst;

    mpz_init(r);
    mpz_init(hw);
    gmp_randinit_default(rndst);

    SAPeks::hashToZn(ksw, w);

    mpz_urandomm(r, rndst, N);
    mpz_powm(hw, r, e, N);
    mpz_mul(ksw, hw, ksw);
    mpz_mod(hw, ksw, N);

    mpz_powm(ksw, hw, d, N);

    mpz_invert(hw, r, N);
    mpz_mul(ksw, hw, ksw);
    mpz_mod(ksw, ksw, N);

    mpz_clear(r);
    mpz_clear(hw);
    gmp_randclear(rndst);
    return 0;
}

int SAPeks::rsaSetup(int lambda) {
   
    mpz_init(N);
    mpz_init(e);
    mpz_init(d);

    mpz_set_str(N, "D82880FD0837BB93E10E5BA1FEEFDA5CD2BB6C888FF5B799A6AE77DCCA7A9A7CD49E9E51D7A309669CD60F6BA25025E6B0DEE9AD3C8FA710D47943639EDD9CF2EEBCFF6E868E8B30E60FFCE6A54B05B4CB18E70E4402B9C7ADC2519866A3F3986A6FE6D09531D19E1D9EC810609940629CE560CE4F59B4C4965976BDF31A11A5B6BB0F6E1F5C54B96EEC7C783B9A16A11700A65ED1FA39FE2253922585310BBB6FBAA9F634B17FA23F04591717EF8E27294C3EB1D1499EC5BFAF5BD01C3BF8E99ADD838C116676F803B84A10DEDB47E9D128DA1773A714B82C787CB469DCAB2DA10DD765505E1047F1DFE025279D80D23EAC4439B5CD353EF66D76A65E305D2BCAB625C7E3E6A24EFB5E6763BB3B925A24BEB4178FF720A7E94867D23E57D22E342EB3DDD67EA8D2E6F0A3E7F41BB0BA03D58F0D28491D07513347905CE9E9AD3DFDAE61DFAFE008016DAC6648F48CF47F531703A57A6987AB4F6B6DBAACBA0ABECDE2D2C5F52FFE91F1CE7728E5C1A4A607D796F0A007218F1A7D07FE913C11", 16);
    mpz_set_str(e, "10001", 16);
    mpz_set_str(d, "403870723CD1CA221A5858B31D7A07675298AA9B3C2225C539B756173BF50717155876F31BDCED7B1617A7073477197B9B8AEEE4303D01C6C749ABD2DA2338B7014D4948ABCE5614F4F8D10DFA423006AE9557D1581B2D6C47A82ADB5D4ADBC403EE91B4966375F7D436176F307CC3AA9AD3BE793D4AFDAA3FE058B24E923BDBAA08ECD7EB3CE70BCCB190A9C47D31E7DB29ED20B816439DCFD7B5653F28CEEBA7A176D18BACBEDB6AB80AB058F140D7F78E2EC1555D3A2337AF392EB78FAF68B0ACFA3B74ACCDC0A0683CBC80B64CEFACAE8CB66817C1773E5674A98D8950C64DC4B1303F0CC96A3FB77D9EB6DAF0902E16E95B541EC76F70D7E40FB82CC1E0E5AAF9C44F4E9FA5F777C2F21D8ED8E1DA67F3EEDE2FEF0086E179F3D2145621D3A2382FA358CDA6903644007F897CBB2944C078FE49A5815413C9CABE1E5A646EE608965CA54E5E4C1DC881881D", 16);
    
    return STS_OK;
}

int SAPeks::setup() {

    pairing_init_set_str(pairing, param.c_str());

    element_init_G1(g, pairing);
    element_random(g);
    element_init_Zr(sk, pairing);
    element_random(sk);
    element_init_G1(pk, pairing);
    element_pow_zn(pk, g, sk);

    return STS_OK;
}


int SAPeks::encrypt(unsigned char *Ca, unsigned char *Cb, const std::string w) {

    unsigned char gt_data[GT_LEN];
    element_t r, tmp1, tmp2, Ca_t;
    mpz_t Delt;
    //随机数r
    element_init_Zr(r, pairing);
    element_init_G1(tmp1, pairing);
    element_init_GT(tmp2, pairing);
    element_init_G1(Ca_t, pairing);

    mpz_init(Delt);


    SAPeks::ksDerived(Delt, w);
    SAPeks::hashToGroup(Delt, tmp1, w);

    element_random(r);
    element_pow_zn(Ca_t, g, r);//Ca = g^r

    element_to_bytes(Ca, Ca_t);


    element_pow_zn(tmp1, tmp1, r);
    element_pairing(tmp2, tmp1, pk);
    
    element_to_bytes(gt_data, tmp2);//Cb = hash(data);
    SHA256(gt_data, GT_LEN, Cb);
    
    element_clear(r);
    element_clear(Ca_t);
    element_clear(tmp1);
    element_clear(tmp2);
    mpz_clear(Delt);
    
    return STS_OK;
}


int SAPeks::trapdoor(unsigned char *Tw, const std::string w) {
    //可验证工作量的陷门
    mpz_t delt;
    element_t Tw_t;
    
    mpz_init(delt);
    element_init_G1(Tw_t,pairing);
    
    SAPeks::ksDerived(delt, w);
    SAPeks::hashToGroup(delt, Tw_t, w);

    element_pow_zn(Tw_t, Tw_t, sk);//Tw = H(w)^sk

    element_to_bytes(Tw,Tw_t);

    mpz_clear(delt);
    element_clear(Tw_t);
    return STS_OK;
}


int SAPeks::test(unsigned char *Tw, unsigned char *A, unsigned char *B) {
    //测试密文与陷门
    if(B == NULL) {
        return STS_ERR;
    }
    element_t tmp,Tw_t,Ca_t;
    unsigned char gt_data[GT_LEN];
    unsigned char hash_data[HASH_LEN];

    element_init_GT(tmp, pairing);
    element_init_G1(Tw_t,pairing);
    element_init_G1(Ca_t,pairing);


    element_from_bytes(Tw_t,Tw);
    element_from_bytes(Ca_t,A);



    element_pairing(tmp, Tw_t, Ca_t);
    element_to_bytes(gt_data, tmp);
    SHA256(gt_data, GT_LEN, hash_data);


    element_clear(Tw_t);
    element_clear(Ca_t);
    element_clear(tmp);



    if(memcmp(hash_data, B, HASH_LEN) == 0) {
        return STS_EQU;
    } else {
        return STS_OK;
    }
}

int SAPeks::exportkey(unsigned char* pk_s, unsigned char* sk_s) {

    element_to_bytes(pk_s, pk);
    element_to_bytes(sk_s, sk);
    
    return STS_OK;
}


int SAPeks::importkey(unsigned char* pk_s, unsigned char* sk_s){

    element_from_bytes(pk,pk_s);
    element_from_bytes(sk,sk_s);

    return STS_OK;
}

