#include <iostream>
#include <iomanip>
#include <fstream>

#include "math/NumberTheory.h"
#include "primality/FermatTest.h"
#include "primality/SolovayStrassenTest.h"
#include "primality/MillerRabinTest.h"
#include "rsa/RsaService.h"
#include "rsa/WienerAttack.h"

static void demoNumberTheory()
{
    std::cout << "=== Number Theory ===" << std::endl;

    mpz_class a = 252, b = 198;
    std::cout << "GCD(" << a << ", " << b << ") = " << NumberTheory::gcd(a, b) << std::endl;

    mpz_class x, y;
    mpz_class g = NumberTheory::exp_gcd(a, b, x, y);
    std::cout << "Extended GCD: " << a << "*(" << x << ") + " << b << "*(" << y << ") = " << g << std::endl;

    mpz_class base = 7, exp = 256, mod = 13;
    std::cout << "mod_pow(" << base << ", " << exp << ", " << mod << ") = "
              << NumberTheory::mod_pow(base, exp, mod) << std::endl;

    std::cout << "Legendre(2, 7) = " << NumberTheory::Legendre(2, 7) << std::endl;
    std::cout << "Jacobi(1001, 9907) = " << NumberTheory::Jacobi(1001, 9907) << std::endl;
    std::cout << std::endl;
}

static void demoPrimalityTests()
{
    std::cout << "=== Primality Tests ===" << std::endl;

    mpz_class prime_candidate("104729");
    mpz_class composite("104730");

    FermatTest fermat;
    SolovayStrassenTest solovay;
    MillerRabinTest miller;

    double prob = 0.999;

    std::cout << "Testing " << prime_candidate << " (expected: prime)" << std::endl;
    std::cout << "  Fermat:           " << (fermat.isPrime(prime_candidate, prob) ? "PRIME" : "COMPOSITE") << std::endl;
    std::cout << "  Solovay-Strassen: " << (solovay.isPrime(prime_candidate, prob) ? "PRIME" : "COMPOSITE") << std::endl;
    std::cout << "  Miller-Rabin:     " << (miller.isPrime(prime_candidate, prob) ? "PRIME" : "COMPOSITE") << std::endl;

    std::cout << "Testing " << composite << " (expected: composite)" << std::endl;
    std::cout << "  Fermat:           " << (fermat.isPrime(composite, prob) ? "PRIME" : "COMPOSITE") << std::endl;
    std::cout << "  Solovay-Strassen: " << (solovay.isPrime(composite, prob) ? "PRIME" : "COMPOSITE") << std::endl;
    std::cout << "  Miller-Rabin:     " << (miller.isPrime(composite, prob) ? "PRIME" : "COMPOSITE") << std::endl;
    std::cout << std::endl;
}

static void demoRsa()
{
    std::cout << "=== RSA Encryption ===" << std::endl;

    RsaService rsa(RsaService::MILLER_RABIN, 0.999, 512);
    rsa.generateKeys();

    std::cout << "Public key (e, n):" << std::endl;
    std::cout << "  e = " << rsa.key_pub.first << std::endl;
    std::cout << "  n = " << rsa.key_pub.second << std::endl;

    mpz_class message(123456789);
    std::cout << "\nOriginal message: " << message << std::endl;

    mpz_class encrypted = rsa.encrypt(message);
    std::cout << "Encrypted: " << encrypted << std::endl;

    mpz_class decrypted = rsa.decrypt(encrypted);
    std::cout << "Decrypted: " << decrypted << std::endl;
    std::cout << "Match: " << (message == decrypted ? "YES" : "NO") << std::endl;
    std::cout << std::endl;
}

static void demoRsaFileEncryption()
{
    std::cout << "=== RSA File Encryption ===" << std::endl;

    const std::string test_file = "rsa_test_input.txt";
    const std::string enc_file  = "rsa_test_encrypted.bin";
    const std::string dec_file  = "rsa_test_decrypted.txt";

    {
        std::ofstream f(test_file);
        f << "Hello from RSA file encryption!";
    }

    RsaService rsa(RsaService::MILLER_RABIN, 0.999, 512);
    rsa.generateKeys();

    rsa.encrypt(test_file, enc_file);
    rsa.decrypt(enc_file, dec_file);

    std::ifstream orig(test_file);
    std::ifstream decr(dec_file);
    std::string orig_content((std::istreambuf_iterator<char>(orig)), std::istreambuf_iterator<char>());
    std::string decr_content((std::istreambuf_iterator<char>(decr)), std::istreambuf_iterator<char>());

    std::cout << "Original:  \"" << orig_content << "\"" << std::endl;
    std::cout << "Decrypted: \"" << decr_content << "\"" << std::endl;
    std::cout << "Match: " << (orig_content == decr_content ? "YES" : "NO") << std::endl;

    std::remove(test_file.c_str());
    std::remove(enc_file.c_str());
    std::remove(dec_file.c_str());
    std::cout << std::endl;
}

static void demoWienerAttack()
{
    std::cout << "=== Wiener Attack ===" << std::endl;

    RsaService rsa(RsaService::MILLER_RABIN, 0.999, 512);
    rsa.generateWeakKeys();

    std::cout << "Weak RSA key generated." << std::endl;
    std::cout << "  e = " << rsa.key_pub.first << std::endl;
    std::cout << "  n = " << rsa.key_pub.second << std::endl;

    WienerAttack attack;
    mpz_class predicted_d = attack.predict_d(rsa.key_pub.first, rsa.key_pub.second);

    std::cout << "Predicted d: " << predicted_d << std::endl;

    if (predicted_d > 0) {
        mpz_class message(42);
        mpz_class encrypted = rsa.encrypt(message);
        mpz_class cracked = NumberTheory::mod_pow(encrypted, predicted_d, rsa.key_pub.second);
        std::cout << "Verification: encrypt(42) -> decrypt with predicted d -> " << cracked << std::endl;
        std::cout << "Attack " << (cracked == message ? "SUCCESSFUL" : "FAILED") << std::endl;
    } else {
        std::cout << "Attack could not recover d" << std::endl;
    }
    std::cout << std::endl;
}

int main()
{
    std::cout << "============================================" << std::endl;
    std::cout << "    RSA & Number Theory Demo" << std::endl;
    std::cout << "============================================" << std::endl;

    demoNumberTheory();
    demoPrimalityTests();
    demoRsa();
    demoRsaFileEncryption();
    demoWienerAttack();

    std::cout << "Done." << std::endl;
    return 0;
}
