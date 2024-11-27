#include <string>
#include <cstring>
#include <iostream>
#include <openssl/sha.h>
#include <pbc/pbc.h>

#define STS_OK 0
#define STS_EQU 1
#define STS_ERR 2
#define GT_LEN 128
#define G1_LEN 128
#define Zr_LEN 20
#define HASH_LEN 32

class IBGEKS {
public:
    IBGEKS();
    ~IBGEKS();

    //INITIAL SK_{gm}
    int setup();

    //INPUT ID OUTPUT GSK
    int join(unsigned char* gsk_output, const std::string& ID);

    //INPUT keyword and gsk, OUTPUT C = [C_a, C_b]
    int encrypt(unsigned char* Ca_out, unsigned char* Cb_out, const std::string& w, const std::string& ID, unsigned char* gsk_input);


    int trapdoor(unsigned char* Tw_output, const std::string& w);

    int test(unsigned char* Tw_input, unsigned char* A_input, const unsigned char* B_input);


    int importkey(unsigned char* sk_s);
    int exportkey(unsigned char* sk_s);    

private:

    std::string param = "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1";
    pairing_t pairing;
    element_t sk;
    element_t gsk;

    // Declare other helper functions if needed
};