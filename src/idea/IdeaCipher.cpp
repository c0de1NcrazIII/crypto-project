#include "IdeaCipher.h"
#include <cstring>

uint16_t IdeaCipher::mulMod(uint16_t a, uint16_t b)
{
    uint32_t x = (a == 0) ? 0x10000u : static_cast<uint32_t>(a);
    uint32_t y = (b == 0) ? 0x10000u : static_cast<uint32_t>(b);
    uint64_t r = static_cast<uint64_t>(x) * y;
    uint32_t lo = static_cast<uint32_t>(r & 0xFFFF);
    uint32_t hi = static_cast<uint32_t>(r >> 16);
    int32_t result = static_cast<int32_t>(lo) - static_cast<int32_t>(hi);
    if (result < 0) result += 0x10001;
    return static_cast<uint16_t>(result & 0xFFFF);
}

uint16_t IdeaCipher::addMod(uint16_t a, uint16_t b)
{
    return static_cast<uint16_t>((static_cast<uint32_t>(a) + b) & 0xFFFF);
}

uint16_t IdeaCipher::mulInverse(uint16_t a)
{
    if (a <= 1) return a;
    uint32_t mod = 0x10001;
    uint32_t x = a;
    int32_t t0 = 1, t1 = 0;
    uint32_t q, y = mod;
    while (y > 0) {
        q = x / y;
        uint32_t tmp = y;
        y = x % y;
        x = tmp;
        int32_t tmp2 = t1;
        t1 = t0 - static_cast<int32_t>(q) * t1;
        t0 = tmp2;
    }
    if (t0 < 0) t0 += static_cast<int32_t>(mod);
    return static_cast<uint16_t>(t0);
}

uint16_t IdeaCipher::addInverse(uint16_t a)
{
    return static_cast<uint16_t>((0x10000 - a) & 0xFFFF);
}

void IdeaCipher::generateEncryptionKeys(const uint8_t* key, uint16_t subkeys[52])
{
    uint16_t full_key[8];
    for (int i = 0; i < 8; i++)
        full_key[i] = (static_cast<uint16_t>(key[2 * i]) << 8) | key[2 * i + 1];

    for (int i = 0; i < 52; i++) {
        subkeys[i] = full_key[i % 8];
        if ((i % 8) == 7 && i < 51) {
            uint8_t raw[16];
            for (int j = 0; j < 8; j++) {
                raw[2 * j] = static_cast<uint8_t>(full_key[j] >> 8);
                raw[2 * j + 1] = static_cast<uint8_t>(full_key[j] & 0xFF);
            }
            // 25-bit left rotation of the 128-bit key
            uint8_t rotated[16];
            int byte_shift = 25 / 8;  // 3
            int bit_shift = 25 % 8;   // 1
            for (int j = 0; j < 16; j++) {
                int src = (j + byte_shift) % 16;
                int src_next = (j + byte_shift + 1) % 16;
                rotated[j] = static_cast<uint8_t>(
                    (raw[src] << bit_shift) | (raw[src_next] >> (8 - bit_shift)));
            }
            for (int j = 0; j < 8; j++)
                full_key[j] = (static_cast<uint16_t>(rotated[2 * j]) << 8) | rotated[2 * j + 1];
        }
    }
}

void IdeaCipher::generateDecryptionKeys(const uint16_t enc[52], uint16_t dec[52])
{
    int ei = 0;
    int di = 48;

    dec[di + 0] = mulInverse(enc[ei + 0]);
    dec[di + 1] = addInverse(enc[ei + 1]);
    dec[di + 2] = addInverse(enc[ei + 2]);
    dec[di + 3] = mulInverse(enc[ei + 3]);
    ei += 4;

    for (int round = 1; round <= 8; round++) {
        di -= 6;
        dec[di + 4] = enc[ei + 0];
        dec[di + 5] = enc[ei + 1];
        ei += 2;

        dec[di + 0] = mulInverse(enc[ei + 0]);
        if (round < 8) {
            dec[di + 1] = addInverse(enc[ei + 2]);
            dec[di + 2] = addInverse(enc[ei + 1]);
        } else {
            dec[di + 1] = addInverse(enc[ei + 1]);
            dec[di + 2] = addInverse(enc[ei + 2]);
        }
        dec[di + 3] = mulInverse(enc[ei + 3]);
        ei += 4;
    }
}

void IdeaCipher::processBlock(const uint8_t* in, uint8_t* out, const uint16_t subkeys[52])
{
    uint16_t x1 = (static_cast<uint16_t>(in[0]) << 8) | in[1];
    uint16_t x2 = (static_cast<uint16_t>(in[2]) << 8) | in[3];
    uint16_t x3 = (static_cast<uint16_t>(in[4]) << 8) | in[5];
    uint16_t x4 = (static_cast<uint16_t>(in[6]) << 8) | in[7];

    int ki = 0;
    for (int round = 0; round < 8; round++) {
        x1 = mulMod(x1, subkeys[ki++]);
        x2 = addMod(x2, subkeys[ki++]);
        x3 = addMod(x3, subkeys[ki++]);
        x4 = mulMod(x4, subkeys[ki++]);

        uint16_t t0 = x1 ^ x3;
        uint16_t t1 = x2 ^ x4;
        t0 = mulMod(t0, subkeys[ki++]);
        t1 = addMod(t1, t0);
        t1 = mulMod(t1, subkeys[ki++]);
        t0 = addMod(t0, t1);

        x1 ^= t1;
        x4 ^= t0;
        uint16_t tmp = x2 ^ t0;
        x2 = x3 ^ t1;
        x3 = tmp;
    }

    // Output transformation
    uint16_t y1 = mulMod(x1, subkeys[ki++]);
    uint16_t y2 = addMod(x3, subkeys[ki++]);
    uint16_t y3 = addMod(x2, subkeys[ki++]);
    uint16_t y4 = mulMod(x4, subkeys[ki++]);

    out[0] = static_cast<uint8_t>(y1 >> 8); out[1] = static_cast<uint8_t>(y1 & 0xFF);
    out[2] = static_cast<uint8_t>(y2 >> 8); out[3] = static_cast<uint8_t>(y2 & 0xFF);
    out[4] = static_cast<uint8_t>(y3 >> 8); out[5] = static_cast<uint8_t>(y3 & 0xFF);
    out[6] = static_cast<uint8_t>(y4 >> 8); out[7] = static_cast<uint8_t>(y4 & 0xFF);
}

void IdeaCipher::encrypt(uint8_t* text, uint8_t* out, uint8_t* key)
{
    uint16_t subkeys[52];
    generateEncryptionKeys(key, subkeys);
    processBlock(text, out, subkeys);
}

void IdeaCipher::decrypt(uint8_t* text, uint8_t* out, uint8_t* key)
{
    uint16_t enc_keys[52], dec_keys[52];
    generateEncryptionKeys(key, enc_keys);
    generateDecryptionKeys(enc_keys, dec_keys);
    processBlock(text, out, dec_keys);
}
