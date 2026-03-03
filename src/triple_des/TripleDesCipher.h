#pragma once
#include "core/BlockCipher.h"
#include "des/DesCipher.h"
#include <cstring>

class TripleDesCipher : public BlockCipher
{
    DesCipher des;
    int key_mode;  // 2 = two-key (16 bytes), 3 = three-key (24 bytes)
public:
    explicit TripleDesCipher(int _key_mode = 3) : key_mode(_key_mode) {}
    ~TripleDesCipher() override = default;

    void encrypt(uint8_t* text, uint8_t* out, uint8_t* key) override
    {
        uint8_t* k1 = key;
        uint8_t* k2 = key + 8;
        uint8_t* k3 = (key_mode == 3) ? key + 16 : key;

        uint8_t tmp1[8] = {0}, tmp2[8] = {0};
        des.encrypt(text, tmp1, k1);
        des.decrypt(tmp1, tmp2, k2);
        des.encrypt(tmp2, out, k3);
    }

    void decrypt(uint8_t* text, uint8_t* out, uint8_t* key) override
    {
        uint8_t* k1 = key;
        uint8_t* k2 = key + 8;
        uint8_t* k3 = (key_mode == 3) ? key + 16 : key;

        uint8_t tmp1[8] = {0}, tmp2[8] = {0};
        des.decrypt(text, tmp1, k3);
        des.encrypt(tmp1, tmp2, k2);
        des.decrypt(tmp2, out, k1);
    }
};
