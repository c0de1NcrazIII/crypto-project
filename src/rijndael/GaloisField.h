#pragma once
#include <cstdint>
#include <vector>

class GaloisField
{
    uint16_t modulus;  // x^8 + low 8 bits, stored as 9-bit value (0x100 | low_byte)

public:
    explicit GaloisField(uint8_t mod_low = 0x1B);

    static uint8_t add(uint8_t a, uint8_t b);
    uint8_t multiply(uint8_t a, uint8_t b) const;
    uint8_t inverse(uint8_t a) const;

    uint8_t getModulusLow() const { return static_cast<uint8_t>(modulus & 0xFF); }

    static bool isIrreducible(uint16_t poly);
    static std::vector<uint8_t> listIrreducibleDegree8();
    static int polyDegree(uint16_t p);
    static uint16_t polyMod(uint16_t a, uint16_t b);
};
