#ifndef PRIMALITYTEST_H
#define PRIMALITYTEST_H

#include <chrono>
#include <vector>
#include <gmpxx.h>

#include "math/NumberTheory.h"


class IPrimalityTest {
public:
    virtual ~IPrimalityTest() = default;

    [[nodiscard]] virtual double getProbForOneIter() const = 0;

    [[nodiscard]] virtual bool isPrime(const mpz_class& num, double min_probability) const = 0;
};

class PrimalityTest : public IPrimalityTest {
public:
    ~PrimalityTest() override = default;

    [[nodiscard]] virtual bool testIteration(const mpz_class& a, const mpz_class& n) const = 0;

    [[nodiscard]] bool isPrime(const mpz_class& num, const double min_probability) const override
    {
        static const std::vector<int> small_primes = {
                2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
                109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
                233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359,
                367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491,
                499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
                643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
                797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
                947, 953, 967, 971, 977, 983, 991, 997 };
        if (num < 2)
        {
            return false;
        }
        for (int prime : small_primes) {
            if (num % prime == 0) return false;
        }

        if (min_probability < 0.5 || min_probability >= 1.0) {
            throw std::invalid_argument("min_probability must be in [0.5, 1)");
        }
        const double prob_for_one_iter = getProbForOneIter();
        double tmp_prob = 1.0;

        gmp_randclass rng(gmp_randinit_default);
        rng.seed(std::chrono::system_clock::now().time_since_epoch().count());

        while ((1 - tmp_prob) < min_probability)
        {
            tmp_prob *= prob_for_one_iter;
            mpz_class a = rng.get_z_range(num - 1);
            if (!testIteration(a, num))
            {
                return false;
            }
        }

        return true;
    }
};

#endif
