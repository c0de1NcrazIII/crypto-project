#include "SolovayStrassenTest.h"
#include "math/NumberTheory.h"

[[nodiscard]] double SolovayStrassenTest::getProbForOneIter() const {
    return 0.5;
}

[[nodiscard]] bool SolovayStrassenTest::testIteration(const mpz_class& a, const mpz_class& n) const {
    mpz_class Jacobi_val = NumberTheory::Jacobi(a, n);
    if (Jacobi_val == -1)
        Jacobi_val += n;

    return (NumberTheory::mod_pow(a, (n - mpz_class(1)) / mpz_class(2), n) == Jacobi_val);
}
