#pragma once
#include "DesKeySchedule.h"
#include "DesRoundFunction.h"
#include "feistel/FeistelCipher.h"
#include "core/BlockCipher.h"

const int IP[] = {
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,  59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
};

const int IP_1[] = {
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25
};

class DesCipher : public BlockCipher
{
    FeistelCipher net;
public:
    DesCipher() : net(FeistelCipher(new DesKeySchedule(), new DesRoundFunction(), 64, 8)) {}
    ~DesCipher() override = default;

    void encrypt(uint8_t* text, uint8_t* out, uint8_t* key) override
    {
        uint8_t tmp[8] = {0};
        permutations(text, 64, IP, 64, tmp);
        net.encryptBlock(tmp, key);
        memset(out, 0, 8);
        permutations(tmp, 64, IP_1, 64, out);
    }

    void decrypt(uint8_t* text, uint8_t* out, uint8_t* key) override
    {
        uint8_t tmp[8] = {0};
        permutations(text, 64, IP, 64, tmp);
        net.decryptBlock(tmp, key);
        memset(out, 0, 8);
        permutations(tmp, 64, IP_1, 64, out);
    }
};
