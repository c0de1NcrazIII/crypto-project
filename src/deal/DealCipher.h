#pragma once
#include "DealKeySchedule.h"
#include "DealRoundFunction.h"
#include "feistel/FeistelCipher.h"
#include "core/BlockCipher.h"
#include <cstring>

class DealCipher : public BlockCipher
{
    FeistelCipher net;
public:
    explicit DealCipher(uint32_t key_size)
        : net(FeistelCipher(new DealKeySchedule(), new DealRoundFunction(), key_size, 16)) {}
    ~DealCipher() override = default;

    void encrypt(uint8_t* text, uint8_t* out, uint8_t* key) override
    {
        if (text != out) memcpy(out, text, 16);
        net.encryptBlock(out, key);
    }

    void decrypt(uint8_t* text, uint8_t* out, uint8_t* key) override
    {
        if (text != out) memcpy(out, text, 16);
        net.decryptBlock(out, key);
    }
};
