#include "PEKS.h"
#include <iostream>
int main() {
    PEKS peks;

    // 设置
    int setupResult = peks.setup();
    if (setupResult != STS_OK) {
        std::cerr << "Error in setup: " << setupResult << std::endl;
        return 1;
    }

    unsigned char pk[G1_LEN];
    unsigned char sk[G1_LEN];    

    peks.exportkey(pk,sk);


    // 加密
    unsigned char Ca[G1_LEN];
    unsigned char Cb[HASH_LEN];
    const char *keyword = "example_keyword";
    int encryptResult = peks.encrypt(Ca, Cb, keyword);
    if (encryptResult != STS_OK) {
        std::cerr << "Error in encrypt: " << encryptResult << std::endl;
        return 1;
    }

    // 陷门
    unsigned char Tw[G1_LEN];
    const char* keyword2 = "example_keyword1";
    int trapdoorResult = peks.trapdoor(Tw, keyword2);
    if (trapdoorResult != STS_OK) {
        std::cerr << "Error in trapdoor: " << trapdoorResult << std::endl;
        return 1;
    }

    // 测试
    int testResult = peks.test(Tw, Ca, Cb);
    if (testResult == STS_EQU) {
        std::cout << "Test passed: Encryption and Trapdoor are equivalent." << std::endl;
    } else {
        std::cerr << "Test failed: Encryption and Trapdoor are not equivalent." << std::endl;
        return 1;
    }

    return 0;
}
