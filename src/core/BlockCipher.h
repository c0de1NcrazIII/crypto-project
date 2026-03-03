#pragma once
#include <cstdint>

class BlockCipher
{
public:
    virtual ~BlockCipher() = default;

    virtual void encrypt(uint8_t* text, uint8_t* out, uint8_t* key) = 0;
    virtual void decrypt(uint8_t* text, uint8_t* out, uint8_t* key) = 0;
};
