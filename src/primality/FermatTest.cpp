#include "FermatTest.h"
#include "math/NumberTheory.h"

[[nodiscard]] double FermatTest::getProbForOneIter() const {
    return 0.5;
}

[[nodiscard]] bool FermatTest::testIteration(const mpz_class& a, const mpz_class& n) const{
    return (NumberTheory::mod_pow(a, n - mpz_class(1), n) == mpz_class(1));
}
