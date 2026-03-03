#ifndef CRYPT_SOLOVAYSTRASSENTEST_H
#define CRYPT_SOLOVAYSTRASSENTEST_H
#include "PrimalityTest.h"

class SolovayStrassenTest : public PrimalityTest {
public:
    [[nodiscard]] double getProbForOneIter() const final;

    [[nodiscard]] bool testIteration(const mpz_class& a, const mpz_class& n) const final;
};

#endif
