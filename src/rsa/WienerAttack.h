#ifndef CRYPT_WIENER_ATTACK_H
#define CRYPT_WIENER_ATTACK_H
#include <gmpxx.h>
#include <vector>


class WienerAttack {
public:
    static std::vector<mpz_class> decompose_to_chained_fraction(const mpz_class& e, const mpz_class& N);

    static std::pair<mpz_class, mpz_class> fromChainFraction(const std::vector<mpz_class>& e, int precision);

    static mpz_class predict_d(const mpz_class& e, const mpz_class& N);
};

#endif
