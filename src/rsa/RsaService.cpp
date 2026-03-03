#include "RsaService.h"

#include <fstream>
#include <random>

#include "primality/FermatTest.h"
#include "primality/MillerRabinTest.h"
#include "primality/SolovayStrassenTest.h"
#include "math/NumberTheory.h"

RsaService::KeyGenerator::KeyGenerator(TestType _test_type, double _min_probability, uint64_t _bit_len) :
        min_probability(_min_probability), bit_len(_bit_len)
{
    switch (_test_type)
    {
        case FERMAT:
        {
            test_type = std::make_unique<FermatTest>();
            break;
        }
        case SOLOVAY_STRASSEN:
        {
            test_type = std::make_unique<SolovayStrassenTest>();
            break;
        }
        case MILLER_RABIN:
        {
            test_type = std::make_unique<MillerRabinTest>();
            break;
        }
        default:
            std::cout << "Test type not recognized" << std::endl;
    }
}

void RsaService::KeyGenerator::generateKeys(RsaService& instance) const {
    std::random_device rd;
    thread_local gmp_randclass rng(gmp_randinit_default);
    rng.seed(rd());

    mpz_class phi_n;

    while (true) {
        mpz_class p = rng.get_z_bits(bit_len) | 1;
        p |= (mpz_class(1) << (bit_len - 1));
        while (!test_type->isPrime(p, min_probability)) {
            p = rng.get_z_bits(bit_len) | 1;
            p |= (mpz_class(1) << (bit_len - 1));

        }

        mpz_class diff(1);
        diff <<= bit_len / 2 - 1;
        mpz_class q = rng.get_z_bits(bit_len) | 1;
        q |= (mpz_class(1) << (bit_len - 1));

        while (abs(p - q) <= diff || !test_type->isPrime(q, min_probability)) {
            q = rng.get_z_bits(bit_len) | 1;
            q |= (mpz_class(1) << (bit_len - 1));

        }

        instance.key_pub.first = 65537;

        mpz_class n = p * q;
        instance.key_pub.second = n;
        instance.key_private.second = n;

        phi_n = (p - 1) * (q - 1);

        mpz_class k;
        mpz_class g = NumberTheory::exp_gcd(instance.key_pub.first, phi_n, instance.key_private.first, k);

        if (g != 1) {
            std::cout << "gcd: " << g << '\n';
            throw std::runtime_error("Inverse doesn't exist");
        }

        instance.key_private.first %= phi_n;
        if (instance.key_private.first < 0) {
            instance.key_private.first += phi_n;
        }
        if (instance.key_private.first > sqrt(sqrt(n)) / 3) {
            break;
        }
    }

    mpz_class tmp = (instance.key_pub.first * instance.key_private.first) % phi_n;

    if (tmp != 1) {
        std::cout << "Error" << '\n';
        std::cout << instance.key_pub.first << '\n';
        std::cout << instance.key_private.first << '\n';
        std::cout << tmp << '\n';
        std::cout << phi_n << '\n';
    }
}

void RsaService::KeyGenerator::generateWeakKeys(RsaService& instance) const {
    std::random_device rd;
    thread_local gmp_randclass rng(gmp_randinit_default);
    rng.seed(rd());

    mpz_class p = rng.get_z_bits(bit_len) | 1;
    p |= (mpz_class(1) << (bit_len - 1));
    while (!test_type->isPrime(p, min_probability))
    {
        p = rng.get_z_bits(bit_len) | 1;
        p |= (mpz_class(1) << (bit_len - 1));
    }



    mpz_class q = rng.get_z_bits(bit_len) | 1;
    q |= (mpz_class(1) << (bit_len - 1));

    while (!test_type->isPrime(q, min_probability))
    {
        q = rng.get_z_bits(bit_len) | 1;
        q |= (mpz_class(1) << (bit_len - 1));
    }
    mpz_class n = p * q;
    mpz_class phi_n = (p - 1) * (q - 1);

    do {
        instance.key_private.first = 2 + (rng.get_z_range(sqrt(sqrt(n)) / 3) | 1);
    } while (NumberTheory::gcd(instance.key_private.first, phi_n) != 1);

    instance.key_pub.second = n;
    instance.key_private.second = n;

    mpz_class k;
    mpz_class g = NumberTheory::exp_gcd(instance.key_private.first, phi_n, instance.key_pub.first, k);


    if (g != 1)
    {
        std::cout << "gcd: " << g << '\n';
        throw std::runtime_error("Inverse doesn't exist");
    }

    instance.key_pub.first %= phi_n;
    if (instance.key_pub.first < 0) {
        instance.key_pub.first += phi_n;
    }

    mpz_class tmp = (instance.key_pub.first * instance.key_private.first) % phi_n;

    if (tmp != 1)
    {
        std::cout << "Error: e*d mod phi != 1" << '\n';
        std::cout << instance.key_pub.first << '\n';
        std::cout << instance.key_private.first << '\n';
        std::cout << tmp << '\n';
        std::cout << phi_n << '\n';
    }
}

RsaService::RsaService(TestType _test_type, double _min_probability, uint64_t _bit_len) :
        keygen(_test_type, _min_probability, _bit_len), bit_len(_bit_len) {}

void RsaService::generateKeys()
{
    keygen.generateKeys(*this);
}

void RsaService::generateWeakKeys()
{
    keygen.generateWeakKeys(*this);
}

mpz_class RsaService::encrypt(const mpz_class& text) const
{
    return NumberTheory::mod_pow(text, key_pub.first, key_pub.second);
}

mpz_class RsaService::decrypt(const mpz_class& text) const
{
    return NumberTheory::mod_pow(text, key_private.first, key_private.second);
}

void RsaService::encrypt(const std::string& inputPath, const std::string& outputPath) const
{
    if (inputPath == outputPath) {
        std::cout << "Input and output files must differ." << std::endl;
        return;
    }

    std::ifstream in(inputPath, std::ios::binary);
    if (!in) {
        std::cout << "Cannot open input file: " << inputPath << std::endl;
        return;
    }

    std::ofstream out(outputPath, std::ios::binary);
    if (!out) {
        std::cout << "Cannot open output file: " << outputPath << std::endl;
        return;
    }

    init_sizes();

    uint8_t buffer[cipher_block];

    const size_t PB = plain_block;
    const size_t CB = cipher_block;
    const size_t KB = key_bytes;

    while (true) {
        in.read(reinterpret_cast<char*>(buffer), PB);
        const size_t bytes_read = in.gcount();

        if (bytes_read == 0) break;

        if (bytes_read < PB) {
            memset(buffer + bytes_read, 0, PB - bytes_read);
        }

        memmove(buffer + KB - bytes_read, buffer, bytes_read);

        buffer[0] = 0x00;
        buffer[1] = 0x02;

        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<uint16_t> dis(1, 255);

        const size_t padding_len = KB - 3 - bytes_read;
        for (size_t i = 0; i < padding_len; ++i) {
            uint8_t r;
            do { r = static_cast<uint8_t>(dis(gen)); } while (r == 0);
            buffer[2 + i] = r;
        }

        buffer[2 + padding_len] = 0x00;

        mpz_class plaintext;
        mpz_import(plaintext.get_mpz_t(), KB, 1, 1, 0, 0, buffer);

        mpz_class ciphertext = encrypt(plaintext);

        size_t export_size;
        mpz_export(buffer, &export_size, 1, 1, 0, 0, ciphertext.get_mpz_t());

        if (export_size < CB) {
            const size_t offset = CB - export_size;
            memmove(buffer + offset, buffer, export_size);
            memset(buffer, 0, offset);
        }

        out.write(reinterpret_cast<const char*>(buffer), CB);
    }
}

void RsaService::decrypt(const std::string& inputPath, const std::string& outputPath) const
{
    if (inputPath == outputPath) {
        std::cout << "Input and output files must differ." << std::endl;
        return;
    }

    std::ifstream in(inputPath, std::ios::binary);
    if (!in) {
        std::cout << "Cannot open input file: " << inputPath << std::endl;
        return;
    }

    std::ofstream out(outputPath, std::ios::binary);
    if (!out) {
        std::cout << "Cannot open output file: " << outputPath << std::endl;
        return;
    }

    init_sizes();

    uint8_t cipher_buffer[cipher_block];
    uint8_t result_buffer[plain_block];

    const size_t CB = cipher_block;
    const size_t KB = key_bytes;

    while (true) {
        in.read(reinterpret_cast<char*>(cipher_buffer), CB);
        const size_t bytes_read = in.gcount();

        if (bytes_read == 0) break;

        if (bytes_read != CB) continue;

        mpz_class ciphertext;
        mpz_import(ciphertext.get_mpz_t(), CB, 1, 1, 0, 0, cipher_buffer);

        mpz_class padded_plaintext = decrypt(ciphertext);

        size_t export_size;
        uint8_t* export_ptr = cipher_buffer;
        mpz_export(export_ptr, &export_size, 1, 1, 0, 0, padded_plaintext.get_mpz_t());

        if (export_size < KB) {
            const size_t offset = KB - export_size;
            memmove(export_ptr + offset, export_ptr, export_size);
            memset(export_ptr, 0, offset);
        }

        if (export_ptr[0] != 0x00 || export_ptr[1] != 0x02) {
            std::cout << "Padding error - skipping block" << std::endl;
            continue;
        }

        size_t i = 2;
        while (i < KB && export_ptr[i] != 0x00) {
            ++i;
        }

        if (i >= KB - 1) {
            std::cout << "No data separator - skipping block" << std::endl;
            continue;
        }

        const size_t data_start = i + 1;
        const size_t data_len = KB - data_start;

        memcpy(result_buffer, export_ptr + data_start, data_len);

        out.write(reinterpret_cast<const char*>(result_buffer), data_len);
    }
}

void RsaService::add_pkcs1_padding(uint8_t* output, const uint8_t* input,
                            size_t input_len) const
{
    init_sizes();
    const size_t KB = key_bytes;
    const size_t padding_len = KB - 3 - input_len;

    output[0] = 0x00;
    output[1] = 0x02;

    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint16_t> dis(1, 255);

    for (size_t i = 0; i < padding_len; ++i) {
        uint8_t r;
        do { r = static_cast<uint8_t>(dis(gen)); } while (r == 0);
        output[2 + i] = r;
    }

    output[2 + padding_len] = 0x00;
    memcpy(output + 2 + padding_len + 1, input, input_len);
}

size_t RsaService::remove_pkcs1_padding(uint8_t* output, const uint8_t* input) const
{
    init_sizes();
    const size_t KB = key_bytes;

    if (input[0] != 0x00 || input[1] != 0x02) {
        return 0;
    }

    size_t i = 2;
    while (i < KB && input[i] != 0x00) {
        ++i;
    }

    if (i >= KB - 1) {
        return 0;
    }

    const size_t data_len = KB - i - 1;
    memcpy(output, input + i + 1, data_len);

    return data_len;
}
