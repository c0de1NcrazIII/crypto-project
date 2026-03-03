#include "WienerAttack.h"
#include "math/NumberTheory.h"

std::vector<mpz_class> WienerAttack::decompose_to_chained_fraction(const mpz_class& e, const mpz_class& N) {
    std::vector<mpz_class> res;
    mpz_class k = e; // 7 25 7 4 3
    mpz_class d = N; // 25 7 4 3 1

    while (d != 0) {
        mpz_class q = k / d;
        res.push_back(q); //0 3 1 1 3

        k = k % d; //7 4 3 1 0

        swap(k, d); // 1 0
        //
    }

    return res;
}

std::pair<mpz_class, mpz_class> WienerAttack::fromChainFraction(const std::vector<mpz_class>& chain, int precision) {
    mpz_class k = 1;
    mpz_class d = chain[precision];
    for (int i = precision - 1; i > 0; i--) {
        k += chain[i] * d;
        swap(k, d);
    }
    return std::make_pair(k, d);
}

mpz_class WienerAttack::predict_d(const mpz_class& e, const mpz_class& N) {
    auto chain = decompose_to_chained_fraction(e, N);

    mpz_class p, q;

    for (int i = 1; i < chain.size(); i++) {
        auto [k, d] = fromChainFraction(chain, i);
        if ((e * d - 1) % k != 0) {
            continue;
        }
        mpz_class b = N - (e * d - 1) / k + 1;
        if (b <= 0) {
            continue;
        }
        mpz_class discriminant = b * b - 4 * N;
        if (discriminant <= 0) {
            continue;
        }

        mpz_class sqrt_disc;
        if (!mpz_perfect_square_p(discriminant.get_mpz_t())) {
            continue;
        }
        mpz_sqrt(sqrt_disc.get_mpz_t(), discriminant.get_mpz_t());

        p = (b - sqrt_disc) / 2;
        q = (b + sqrt_disc) / 2;

        if (p <= 0 || q <= 0) {
            continue;
        }

        if (q * p == N)
            return d;
    }
    return -1;
}
