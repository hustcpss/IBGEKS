#include "PAEKS17.h"
#include <iostream>

int main() {
    PAEKS17 paeks;

    // Setup
    int setupResult = paeks.setup();
    if (setupResult != STS_OK) {
        std::cerr << "Setup failed." << std::endl;
        return setupResult;
    }

    // Encryption
    unsigned char Ca[G1_LEN];
    unsigned char Cb2[G1_LEN];
    int encryptResult = paeks.encrypt(Ca, Cb2, "test");
    if (encryptResult != STS_OK) {
        std::cerr << "Encryption failed." << std::endl;
        return encryptResult;
    }

    // Trapdoor
    unsigned char Tw2[GT_LEN];
    int trapdoorResult = paeks.trapdoor(Tw2, "test");
    if (trapdoorResult != STS_OK) {
        std::cerr << "Trapdoor generation failed." << std::endl;
        return trapdoorResult;
    }

    // Test
    int testResult = paeks.test(Tw2, Ca, Cb2);
    if (testResult == STS_EQU) {
        std::cout << "Test passed: Ciphertext matches trapdoor." << std::endl;
    } else {
        std::cerr << "Test failed: Ciphertext does not match trapdoor." << std::endl;
        return testResult;
    }

    return 0;
}
