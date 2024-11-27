#include "IBGEKS.h"

IBGEKS::IBGEKS() {

    pairing_init_set_str(pairing, param.c_str());
    element_init_Zr(sk, pairing);
    element_init_G1(gsk, pairing);
}

IBGEKS::~IBGEKS() {

    element_clear(sk);
    element_clear(gsk);
    pairing_clear(pairing);
}

int IBGEKS::setup() {
    element_random(sk);
    return STS_OK;
}

int IBGEKS::join(unsigned char* gsk_output, const std::string& ID) {
    
    element_t tmp1;
    element_init_G1(tmp1, pairing);
    element_from_hash(tmp1, (void*)ID.c_str(), ID.length());

    element_pow_zn(gsk, tmp1, sk);

    element_to_bytes(gsk_output,gsk);

    element_clear(tmp1);
    return STS_OK;
}

int IBGEKS::encrypt(unsigned char* Ca_out, unsigned char* Cb_out, const std::string& w, const std::string& ID, unsigned char* gsk_input) {
    if (w.empty()) {
        return STS_ERR;
    }

    unsigned char gt_data[GT_LEN];
    element_t r, Ca, tmp1, tmp2, tmp3;

    element_from_bytes(gsk,gsk_input);

    element_init_Zr(r, pairing);
    element_init_G1(Ca, pairing);
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);
    element_init_GT(tmp3, pairing);

    element_from_hash(tmp1, (void*)ID.c_str(), ID.length());
    element_from_hash(tmp2, (void*)w.c_str(), w.length());

    element_random(r);
    element_pow_zn(Ca, tmp1, r); //Ca = H_1(ID)^r
    element_to_bytes(Ca_out,Ca); //OUTPUT Ca

    element_pow_zn(tmp2, tmp2, r); //tmp2 = H_2(w)^r
    element_pairing(tmp3, gsk, tmp2); //tmp3 = e(gsk,H_2(w)^r)
    element_to_bytes(gt_data, tmp3);
    SHA256(gt_data, GT_LEN, Cb_out); //OUTPUT Cb

    element_clear(r);
    element_clear(Ca);
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(tmp3);

    return STS_OK;
}

int IBGEKS::trapdoor(unsigned char* Tw_output, const std::string& w) {
    if (w.empty()) {
        return STS_ERR;
    }

    element_t Tw;
    element_init_G1(Tw,pairing);

    element_from_hash(Tw, (void*)w.c_str(), w.length());
    element_pow_zn(Tw, Tw, sk);

    element_to_bytes(Tw_output,Tw);
    element_clear(Tw);

    return STS_OK;
}

int IBGEKS::test(unsigned char* Tw_input, unsigned char* A_input, const unsigned char* B_input) {
    if (B_input == nullptr) {
        return STS_ERR;
    }

    element_t tmp,A,Tw;
    unsigned char gt_data[GT_LEN];
    unsigned char hash_data[HASH_LEN];

    element_init_GT(tmp, pairing);
    element_init_G1(Tw,pairing);
    element_init_G1(A,pairing);

    element_from_bytes(A,A_input);
    element_from_bytes(Tw,Tw_input);


    element_pairing(tmp, Tw, A);
    element_to_bytes(gt_data, tmp);
    SHA256(gt_data, GT_LEN, hash_data);


    element_clear(tmp);
    element_clear(Tw);
    element_clear(A);

    if (memcmp(hash_data, B_input, HASH_LEN) == 0) {
        return STS_EQU;
    } else {
        return STS_OK;
    }
}

int IBGEKS::exportkey(unsigned char* sk_s) {

    element_to_bytes(sk_s, sk);
    return STS_OK;
}


int IBGEKS::importkey(unsigned char* sk_s){

    element_from_bytes(sk,sk_s);
    return STS_OK;
}