#include "MillerRabinTest.h"

#include "math/NumberTheory.h"

[[nodiscard]] double MillerRabinTest::getProbForOneIter() const {
    return 0.25;
}

[[nodiscard]] bool MillerRabinTest::testIteration(const mpz_class& a, const mpz_class& n) const {
    mpz_class d = n - 1;
    mpz_class s = 0;
    const mpz_class n_minus_one = n - 1;
    while (d % 2 == 0) {
        d /= mpz_class(2);
        ++s;
    }

    mpz_class x = NumberTheory::mod_pow(a, d, n);
    if (x == mpz_class(1) || x == n_minus_one)
        return true;

    for (mpz_class i = 0; i < s; ++i) {
        x = x * x % n;
        if (x == n_minus_one)
            return true;
    }

    return false;
}
