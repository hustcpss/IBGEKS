#include "PAEKS20.h"
#include <iostream>

int main() {
    // 使用PAEKS20类
    PAEKS20 paeks;
    unsigned char Ca[G1_LEN];
    unsigned char Tw[G1_LEN];
    unsigned char Cb[HASH_LEN];

    // 使用paeks20_encrypt加密
    std::cout << "stage-1" << std::endl;

    paeks.encrypt(Ca, Cb, "example_word");

    std::cout << "stage-2" << std::endl;

    // 使用paeks20_trapdoor生成陷门
    paeks.trapdoor(Tw, "example_word");

    std::cout << "stage-3" << std::endl;

    // 使用paeks20_test测试密文与陷门
    int result = paeks.test(Tw, Ca, Cb);

    std::cout << "stage-4" << std::endl;

    if (result == STS_EQU) {
        std::cout << "Test Passed: The ciphertext and trapdoor match." << std::endl;
    } else {
        std::cout << "Test Failed: The ciphertext and trapdoor do not match." << std::endl;
    }

    return 0;
}
