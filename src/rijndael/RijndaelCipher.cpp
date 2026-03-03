#include "RijndaelCipher.h"
#include <cstring>
#include <algorithm>

RijndaelCipher::RijndaelCipher(uint32_t block_bits, uint32_t key_bits, uint8_t gf_modulus)
    : block_bytes(block_bits / 8), key_bytes(key_bits / 8),
      Nb(block_bits / 32), Nk(key_bits / 32),
      Nr(std::max(Nb, Nk) + 6),
      gf(gf_modulus)
{
    initSBox();
}

void RijndaelCipher::initSBox()
{
    const uint8_t affine_c = 0x63;
    for (int i = 0; i < 256; i++) {
        uint8_t inv = gf.inverse(static_cast<uint8_t>(i));
        uint8_t s = inv;
        uint8_t result = 0;
        for (int bit = 0; bit < 8; bit++) {
            uint8_t val = ((s >> bit) & 1) ^
                          ((s >> ((bit + 4) % 8)) & 1) ^
                          ((s >> ((bit + 5) % 8)) & 1) ^
                          ((s >> ((bit + 6) % 8)) & 1) ^
                          ((s >> ((bit + 7) % 8)) & 1) ^
                          ((affine_c >> bit) & 1);
            result |= (val << bit);
        }
        sbox[i] = result;
    }
    for (int i = 0; i < 256; i++)
        inv_sbox[sbox[i]] = static_cast<uint8_t>(i);
}

uint32_t RijndaelCipher::subWord(uint32_t w) const
{
    return (static_cast<uint32_t>(sbox[(w >> 24) & 0xFF]) << 24) |
           (static_cast<uint32_t>(sbox[(w >> 16) & 0xFF]) << 16) |
           (static_cast<uint32_t>(sbox[(w >> 8) & 0xFF]) << 8) |
           (static_cast<uint32_t>(sbox[w & 0xFF]));
}

uint32_t RijndaelCipher::rotWord(uint32_t w)
{
    return (w << 8) | (w >> 24);
}

void RijndaelCipher::keyExpansion(const uint8_t* key, std::vector<uint32_t>& w) const
{
    uint32_t totalWords = Nb * (Nr + 1);
    w.resize(totalWords);

    for (uint32_t i = 0; i < Nk; i++) {
        uint32_t idx = 4 * i;
        w[i] = (static_cast<uint32_t>(key[idx]) << 24) |
               (static_cast<uint32_t>(key[idx + 1]) << 16) |
               (static_cast<uint32_t>(key[idx + 2]) << 8) |
               (static_cast<uint32_t>(key[idx + 3]));
    }

    uint8_t rc = 1;
    for (uint32_t i = Nk; i < totalWords; i++) {
        uint32_t temp = w[i - 1];
        if (i % Nk == 0) {
            temp = subWord(rotWord(temp));
            temp ^= (static_cast<uint32_t>(rc) << 24);
            rc = gf.multiply(rc, 0x02);
        } else if (Nk > 6 && (i % Nk) == 4) {
            temp = subWord(temp);
        }
        w[i] = w[i - Nk] ^ temp;
    }
}

void RijndaelCipher::addRoundKey(uint8_t* state, const std::vector<uint32_t>& w, uint32_t round) const
{
    for (uint32_t c = 0; c < Nb; c++) {
        uint32_t wk = w[round * Nb + c];
        state[c * 4 + 0] ^= (wk >> 24) & 0xFF;
        state[c * 4 + 1] ^= (wk >> 16) & 0xFF;
        state[c * 4 + 2] ^= (wk >> 8) & 0xFF;
        state[c * 4 + 3] ^= wk & 0xFF;
    }
}

void RijndaelCipher::subBytes(uint8_t* state) const
{
    for (uint32_t i = 0; i < 4 * Nb; i++)
        state[i] = sbox[state[i]];
}

void RijndaelCipher::invSubBytes(uint8_t* state) const
{
    for (uint32_t i = 0; i < 4 * Nb; i++)
        state[i] = inv_sbox[state[i]];
}

void RijndaelCipher::shiftRows(uint8_t* state) const
{
    uint8_t tmp[32];
    memcpy(tmp, state, 4 * Nb);

    int shifts[4];
    shifts[0] = 0;
    if (Nb <= 6) {
        shifts[1] = 1; shifts[2] = 2; shifts[3] = 3;
    } else {
        shifts[1] = 1; shifts[2] = 3; shifts[3] = 4;
    }

    for (uint32_t row = 1; row < 4; row++) {
        for (uint32_t col = 0; col < Nb; col++) {
            state[col * 4 + row] = tmp[((col + shifts[row]) % Nb) * 4 + row];
        }
    }
}

void RijndaelCipher::invShiftRows(uint8_t* state) const
{
    uint8_t tmp[32];
    memcpy(tmp, state, 4 * Nb);

    int shifts[4];
    shifts[0] = 0;
    if (Nb <= 6) {
        shifts[1] = 1; shifts[2] = 2; shifts[3] = 3;
    } else {
        shifts[1] = 1; shifts[2] = 3; shifts[3] = 4;
    }

    for (uint32_t row = 1; row < 4; row++) {
        for (uint32_t col = 0; col < Nb; col++) {
            state[((col + shifts[row]) % Nb) * 4 + row] = tmp[col * 4 + row];
        }
    }
}

void RijndaelCipher::mixColumns(uint8_t* state) const
{
    for (uint32_t c = 0; c < Nb; c++) {
        uint8_t* col = state + c * 4;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = gf.multiply(0x02, a0) ^ gf.multiply(0x03, a1) ^ a2 ^ a3;
        col[1] = a0 ^ gf.multiply(0x02, a1) ^ gf.multiply(0x03, a2) ^ a3;
        col[2] = a0 ^ a1 ^ gf.multiply(0x02, a2) ^ gf.multiply(0x03, a3);
        col[3] = gf.multiply(0x03, a0) ^ a1 ^ a2 ^ gf.multiply(0x02, a3);
    }
}

void RijndaelCipher::invMixColumns(uint8_t* state) const
{
    for (uint32_t c = 0; c < Nb; c++) {
        uint8_t* col = state + c * 4;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = gf.multiply(0x0e, a0) ^ gf.multiply(0x0b, a1) ^ gf.multiply(0x0d, a2) ^ gf.multiply(0x09, a3);
        col[1] = gf.multiply(0x09, a0) ^ gf.multiply(0x0e, a1) ^ gf.multiply(0x0b, a2) ^ gf.multiply(0x0d, a3);
        col[2] = gf.multiply(0x0d, a0) ^ gf.multiply(0x09, a1) ^ gf.multiply(0x0e, a2) ^ gf.multiply(0x0b, a3);
        col[3] = gf.multiply(0x0b, a0) ^ gf.multiply(0x0d, a1) ^ gf.multiply(0x09, a2) ^ gf.multiply(0x0e, a3);
    }
}

void RijndaelCipher::encrypt(uint8_t* text, uint8_t* out, uint8_t* key)
{
    std::vector<uint32_t> w;
    keyExpansion(key, w);

    uint8_t state[32];
    for (uint32_t c = 0; c < Nb; c++)
        for (uint32_t r = 0; r < 4; r++)
            state[c * 4 + r] = text[r * Nb + c];

    addRoundKey(state, w, 0);

    for (uint32_t round = 1; round < Nr; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, w, round);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, w, Nr);

    for (uint32_t c = 0; c < Nb; c++)
        for (uint32_t r = 0; r < 4; r++)
            out[r * Nb + c] = state[c * 4 + r];
}

void RijndaelCipher::decrypt(uint8_t* text, uint8_t* out, uint8_t* key)
{
    std::vector<uint32_t> w;
    keyExpansion(key, w);

    uint8_t state[32];
    for (uint32_t c = 0; c < Nb; c++)
        for (uint32_t r = 0; r < 4; r++)
            state[c * 4 + r] = text[r * Nb + c];

    addRoundKey(state, w, Nr);

    for (uint32_t round = Nr - 1; round >= 1; round--) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, w, round);
        invMixColumns(state);
    }

    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, w, 0);

    for (uint32_t c = 0; c < Nb; c++)
        for (uint32_t r = 0; r < 4; r++)
            out[r * Nb + c] = state[c * 4 + r];
}
