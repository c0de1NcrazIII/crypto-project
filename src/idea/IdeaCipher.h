#pragma once
#include "core/BlockCipher.h"
#include <cstdint>

class IdeaCipher : public BlockCipher
{
    static uint16_t mulMod(uint16_t a, uint16_t b);
    static uint16_t addMod(uint16_t a, uint16_t b);
    static uint16_t mulInverse(uint16_t a);
    static uint16_t addInverse(uint16_t a);

    static void generateEncryptionKeys(const uint8_t* key, uint16_t subkeys[52]);
    static void generateDecryptionKeys(const uint16_t enc_keys[52], uint16_t dec_keys[52]);

public:
    IdeaCipher() = default;
    ~IdeaCipher() override = default;

    void encrypt(uint8_t* text, uint8_t* out, uint8_t* key) override;
    void decrypt(uint8_t* text, uint8_t* out, uint8_t* key) override;

private:
    static void processBlock(const uint8_t* in, uint8_t* out, const uint16_t subkeys[52]);
};
