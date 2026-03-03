#ifndef CRYPT_FERMAT_TEST_H
#define CRYPT_FERMAT_TEST_H
#include "PrimalityTest.h"

class FermatTest : public PrimalityTest {
public:
    [[nodiscard]] double getProbForOneIter() const final;

    [[nodiscard]] bool testIteration(const mpz_class& a, const mpz_class& n) const final;
};


#endif
