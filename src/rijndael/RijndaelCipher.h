#pragma once
#include "core/BlockCipher.h"
#include "GaloisField.h"
#include <cstdint>
#include <vector>

class RijndaelCipher : public BlockCipher
{
    uint32_t block_bytes;   // 16, 24, or 32
    uint32_t key_bytes;     // 16, 24, or 32
    uint32_t Nb;            // block words (4, 6, 8)
    uint32_t Nk;            // key words (4, 6, 8)
    uint32_t Nr;            // rounds

    GaloisField gf;
    uint8_t sbox[256];
    uint8_t inv_sbox[256];

    void initSBox();
    void keyExpansion(const uint8_t* key, std::vector<uint32_t>& w) const;
    uint32_t subWord(uint32_t w) const;
    static uint32_t rotWord(uint32_t w);

    void subBytes(uint8_t* state) const;
    void invSubBytes(uint8_t* state) const;
    void shiftRows(uint8_t* state) const;
    void invShiftRows(uint8_t* state) const;
    void mixColumns(uint8_t* state) const;
    void invMixColumns(uint8_t* state) const;
    void addRoundKey(uint8_t* state, const std::vector<uint32_t>& w, uint32_t round) const;

public:
    RijndaelCipher(uint32_t block_bits, uint32_t key_bits, uint8_t gf_modulus = 0x1B);
    ~RijndaelCipher() override = default;

    void encrypt(uint8_t* text, uint8_t* out, uint8_t* key) override;
    void decrypt(uint8_t* text, uint8_t* out, uint8_t* key) override;

    uint32_t getBlockSize() const { return block_bytes; }
};
