#include "GaloisField.h"

GaloisField::GaloisField(uint8_t mod_low) : modulus(0x100 | mod_low) {}

uint8_t GaloisField::add(uint8_t a, uint8_t b)
{
    return a ^ b;
}

uint8_t GaloisField::multiply(uint8_t a, uint8_t b) const
{
    uint16_t x = a;
    uint16_t y = b;
    uint16_t result = 0;
    while (y > 0) {
        if (y & 1)
            result ^= x;
        x <<= 1;
        if (x & 0x100)
            x ^= modulus;
        y >>= 1;
    }
    return static_cast<uint8_t>(result);
}

uint8_t GaloisField::inverse(uint8_t a) const
{
    if (a == 0) return 0;
    uint8_t result = a;
    for (int i = 0; i < 6; i++) {
        result = multiply(result, result);
        result = multiply(result, a);
    }
    result = multiply(result, result);
    return result;
}

int GaloisField::polyDegree(uint16_t p)
{
    int d = -1;
    while (p > 0) { d++; p >>= 1; }
    return d;
}

uint16_t GaloisField::polyMod(uint16_t a, uint16_t b)
{
    int db = polyDegree(b);
    if (db < 0) return 0;
    int da = polyDegree(a);
    while (da >= db) {
        a ^= (b << (da - db));
        da = polyDegree(a);
    }
    return a;
}

bool GaloisField::isIrreducible(uint16_t poly)
{
    int deg = polyDegree(poly);
    if (deg <= 0) return false;
    if (deg == 1) return true;

    for (uint16_t divisor = 2; ; divisor++) {
        int dd = polyDegree(divisor);
        if (dd > deg / 2) break;
        if (polyMod(poly, divisor) == 0)
            return false;
    }
    return true;
}

std::vector<uint8_t> GaloisField::listIrreducibleDegree8()
{
    std::vector<uint8_t> result;
    for (uint16_t low = 0; low < 256; low++) {
        uint16_t poly = 0x100 | low;
        if (isIrreducible(poly))
            result.push_back(static_cast<uint8_t>(low));
    }
    return result;
}
