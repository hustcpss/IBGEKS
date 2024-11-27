#include "SA_PEKS.h"
#include <iostream>

int main() {


    SAPeks saPeks;

    unsigned char  Ca[G1_LEN],Cb[HASH_LEN],Tw[G1_LEN];

    // 加密
    saPeks.encrypt(Ca, Cb, "test_keyword");

    // 生成陷门
    saPeks.trapdoor(Tw, "test_keyword");

    // 测试
    int result = saPeks.test(Tw, Ca, Cb);

    if (result == STS_EQU) {
        std::cout << "Test passed: Encrypted keyword matches trapdoor." << std::endl;
    } else {
        std::cout << "Test failed: Encrypted keyword does not match trapdoor." << std::endl;
    }

    return 0;
}
