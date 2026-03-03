#ifndef CRYPT_MILLERRABINTEST_H
#define CRYPT_MILLERRABINTEST_H
#include "PrimalityTest.h"


class MillerRabinTest : public PrimalityTest {
public:
    [[nodiscard]] double getProbForOneIter() const final;

    [[nodiscard]] bool testIteration(const mpz_class& a, const mpz_class& n) const final;
};
#endif
