#include <string>
#include <cstring>
#include <openssl/sha.h>
#include <pbc/pbc.h>


#define STS_OK 0
#define STS_EQU 1
#define STS_ERR 2
#define G1_LEN 128
#define GT_LEN 128
#define Zr_LEN 20
#define HASH_LEN 32

class PEKS {
private:
    pairing_t pairing;
    std::string param = "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1";
    element_t g;
    element_t pk;
    element_t sk;

public:
    PEKS();
    ~PEKS();

    int setup();
    int encrypt(unsigned char* Ca, unsigned char *Cb, const char *w);
    int trapdoor(unsigned char* Tw, const char *w);
    int test(unsigned char* Tw, unsigned char* A, const unsigned char *B);
    

    int exportkey(unsigned char* pk_s, unsigned char* sk_s);
    int importkey(unsigned char* pk_s, unsigned char* sk_s);
};