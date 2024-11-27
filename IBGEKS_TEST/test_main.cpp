#include <iostream>
#include "IBGEKS.h"  // 替换成你的头文件名称

int main() {
    IBGEKS ibgeks;

    std::cout<< "start" << std::endl;

    // 设置
    int setupResult = ibgeks.setup();
    if (setupResult != STS_OK) {
        std::cerr << "Error in setup: " << setupResult << std::endl;
        return 1;
    }

    std::cout<< "stage-1" << std::endl;

    // 参与者加入
    const std::string participantID = "Alice";
    unsigned char gsk[G1_LEN]={0};
    int joinResult = ibgeks.join(gsk,participantID);
    if (joinResult != STS_OK) {
        std::cerr << "Error in join: " << joinResult << std::endl;
        return 1;
    }

    std::cout<< "stage-2" << std::endl;

    // 加密
    unsigned char Ca[G1_LEN]={0};
    unsigned char Cb[HASH_LEN]={0};
    const std::string keyword = "Security";
    int encryptResult = ibgeks.encrypt(Ca, Cb, keyword, participantID, gsk);
    if (encryptResult != STS_OK) {
        std::cerr << "Error in encrypt: " << encryptResult << std::endl;
        return 1;
    }

    std::cout<< "stage-3" << std::endl;

    // 陷阱门
    unsigned char Tw[G1_LEN]={0};
    int trapdoorResult = ibgeks.trapdoor(Tw, keyword);
    if (trapdoorResult != STS_OK) {
        std::cerr << "Error in trapdoor: " << trapdoorResult << std::endl;
        return 1;
    }

    std::cout<< "stage-4" << std::endl;

    // 测试
    int testResult = ibgeks.test(Tw, Ca, Cb);
    if (testResult == STS_EQU) {
        std::cout << "Test passed: Tw and Ca match." << std::endl;
    } else {
        std::cerr << "Test failed: Tw and Ca do not match." << std::endl;
        return 1;
    }

    std::cout<< "stage-5" << std::endl;

    return 0;
}