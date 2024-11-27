#include "PAEKS17.h"

PAEKS17::PAEKS17() {
    // Constructor for initializing the pairing and elements
    pairing_init_set_str(pairing, param.c_str());
    element_init_G2(g, pairing);
    element_init_G2(pk, pairing);
    element_init_Zr(sk, pairing);
    element_init_G2(pk2, pairing);
    element_init_Zr(sk2, pairing);
}

PAEKS17::~PAEKS17() {
    // Destructor for cleaning up allocated memory
    element_clear(g);
    element_clear(pk);
    element_clear(sk);
    element_clear(pk2);
    element_clear(sk2);
    pairing_clear(pairing);
}

int PAEKS17::setup() {
    // Initialization
    element_random(g);
    element_random(sk);
    element_pow_zn(pk, g, sk);

    element_random(sk2);
    element_pow_zn(pk2, g, sk2);

    return STS_OK;
}

int PAEKS17::encrypt(unsigned char* Ca, unsigned char* Cb2, const std::string& w) {
    // Encryption
    if (w.empty()) {
        return STS_ERR;
    }

    element_t r, tmp1, tmp2, Ca_e, Cb_e;
    element_init_Zr(r, pairing);
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);
    element_init_G1(Ca_e, pairing);
    element_init_G2(Cb_e, pairing);

    element_from_hash(tmp1, (void*)w.c_str(), w.length());

    element_random(r);
    element_pow_zn(tmp1, tmp1, sk2);
    element_pow_zn(tmp2, g, r);
    element_mul(Ca_e, tmp1, tmp2);
    element_pow_zn(Cb_e, pk, r);//Cb = pk^r
    
    // Convert elements to bytes

    element_to_bytes(Ca, Ca_e);
    element_to_bytes(Cb2,Cb_e);

    element_clear(r);
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(Ca_e);
    element_clear(Cb_e);

    return STS_OK;
}

int PAEKS17::trapdoor(unsigned char* Tw2, const std::string& w) {
    // Trapdoor
    if (w.empty()) {
        return STS_ERR;
    }

    element_t tmp1,Tw2_e;
    element_init_G1(tmp1, pairing);
    element_init_GT(Tw2_e, pairing);

    element_from_hash(tmp1, (void*)w.c_str(), w.length());

    element_pow_zn(tmp1, tmp1, sk);
    element_pairing(Tw2_e, tmp1, pk2);//Cb = e(H(w)^sk,pk2)
    
    // Convert element to bytes
    element_to_bytes(Tw2, Tw2_e);

    element_clear(Tw2_e);
    element_clear(tmp1);

    return STS_OK;
}

int PAEKS17::test(unsigned char* Tw2, unsigned char* A, unsigned char* B) {
    // Test ciphertext and trapdoor
    if (B == NULL) {
        return STS_ERR;
    }

    element_t tmp1, tmp2, tmp3;
    element_t Tw2_e,A_e,B_e;


    element_init_GT(Tw2_e, pairing);
    element_init_G1(A_e, pairing);
    element_init_G1(B_e, pairing);

    element_from_bytes(A_e,A);
    element_from_bytes(B_e,B);
    element_from_bytes(Tw2_e,Tw2);



    element_init_GT(tmp1, pairing);
    element_pairing(tmp1, B_e, g);

    element_init_GT(tmp2, pairing);
    element_mul(tmp2, Tw2_e, tmp1);

    element_init_GT(tmp3, pairing);
    element_pairing(tmp3, A_e, pk);

    if (element_cmp(tmp2, tmp3) == 0) {
        element_clear(tmp1);
        element_clear(tmp2);
        element_clear(tmp3);
        element_clear(A_e);
        element_clear(B_e);
        element_clear(Tw2_e);
        return STS_EQU;
    } else {
        element_clear(tmp1);
        element_clear(tmp2);
        element_clear(tmp3);
        element_clear(A_e);
        element_clear(B_e);
        element_clear(Tw2_e);        
        return STS_OK;
    }
}

int PAEKS17::exportkey(unsigned char* pk_s, unsigned char* sk_s) {

    element_to_bytes(pk_s, pk);
    element_to_bytes(sk_s, sk);
    
    return STS_OK;
}


int PAEKS17::importkey(unsigned char* pk_s, unsigned char* sk_s){

    element_from_bytes(pk,pk_s);
    element_from_bytes(sk,sk_s);

    return STS_OK;
}



