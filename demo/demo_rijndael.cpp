#include <iostream>
#include <iomanip>
#include <cstring>

#include "rijndael/GaloisField.h"
#include "rijndael/RijndaelCipher.h"
#include "modes/CipherContext.h"

static void printHex(const uint8_t* data, size_t len, const char* label)
{
    std::cout << label << ": ";
    for (size_t i = 0; i < len; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    std::cout << std::dec << std::endl;
}

static void demoGaloisField()
{
    std::cout << "=== GF(2^8) Arithmetic ===" << std::endl;

    GaloisField gf(0x1B);

    std::cout << "Using modulus: x^8 + x^4 + x^3 + x + 1 (0x11B)" << std::endl;
    std::cout << "add(0x57, 0x83)  = 0x" << std::hex << (int)GaloisField::add(0x57, 0x83) << std::endl;
    std::cout << "mul(0x57, 0x83)  = 0x" << (int)gf.multiply(0x57, 0x83) << std::endl;
    std::cout << "mul(0x57, 0x13)  = 0x" << (int)gf.multiply(0x57, 0x13) << std::endl;

    uint8_t a = 0x53;
    uint8_t inv = gf.inverse(a);
    uint8_t check = gf.multiply(a, inv);
    std::cout << "inv(0x" << (int)a << ") = 0x" << (int)inv
              << ", verify: 0x" << (int)a << " * 0x" << (int)inv
              << " = 0x" << (int)check << std::dec << std::endl;
    std::cout << std::endl;
}

static void demoIrreduciblePolynomials()
{
    std::cout << "=== Irreducible Polynomials of degree 8 over GF(2) ===" << std::endl;

    auto polys = GaloisField::listIrreducibleDegree8();
    std::cout << "Found " << polys.size() << " irreducible polynomials:" << std::endl;

    for (size_t i = 0; i < polys.size(); i++) {
        std::cout << "  0x" << std::hex << std::setw(2) << std::setfill('0')
                  << (0x100 | polys[i]);
        if ((i + 1) % 10 == 0) std::cout << std::endl;
        else std::cout << " ";
    }
    std::cout << std::dec << std::endl << std::endl;
}

static void demoRijndael(uint32_t block_bits, uint32_t key_bits, uint8_t gf_mod = 0x1B)
{
    uint32_t block_bytes = block_bits / 8;
    uint32_t key_bytes = key_bits / 8;

    std::cout << "=== Rijndael " << block_bits << "/" << key_bits;
    if (gf_mod != 0x1B) std::cout << " (mod=0x" << std::hex << (0x100 | gf_mod) << std::dec << ")";
    std::cout << " ===" << std::endl;

    auto* plaintext = new uint8_t[block_bytes]();
    auto* key = new uint8_t[key_bytes]();
    auto* encrypted = new uint8_t[block_bytes]();
    auto* decrypted = new uint8_t[block_bytes]();

    for (uint32_t i = 0; i < block_bytes; i++) plaintext[i] = i;
    for (uint32_t i = 0; i < key_bytes; i++) key[i] = (i * 17 + 5) & 0xFF;

    RijndaelCipher cipher(block_bits, key_bits, gf_mod);

    printHex(plaintext, block_bytes, "Plaintext ");
    printHex(key, key_bytes, "Key       ");

    cipher.encrypt(plaintext, encrypted, key);
    printHex(encrypted, block_bytes, "Encrypted ");

    cipher.decrypt(encrypted, decrypted, key);
    printHex(decrypted, block_bytes, "Decrypted ");

    std::cout << "Match: " << (memcmp(plaintext, decrypted, block_bytes) == 0 ? "YES" : "NO") << std::endl;
    std::cout << std::endl;

    delete[] plaintext;
    delete[] key;
    delete[] encrypted;
    delete[] decrypted;
}

static void demoRijndaelModes()
{
    std::cout << "=== Rijndael with Cipher Modes ===" << std::endl;

    uint8_t key[16];
    for (int i = 0; i < 16; i++) key[i] = (i * 17 + 5) & 0xFF;
    uint8_t iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    std::string plain = "Rijndael (AES) encryption with all cipher modes working correctly.";
    auto* data = reinterpret_cast<uint8_t*>(plain.data());
    uint64_t data_len = plain.size();

    const char* mode_names[] = {"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "RandomDelta"};
    Mode modes[] = {Mode::ECB, Mode::CBC, Mode::PCBC, Mode::CFB, Mode::OFB, Mode::CTR, Mode::RandomDelta};

    auto* cipher = new RijndaelCipher(128, 128);

    for (int i = 0; i < 7; i++) {
        uint64_t enc_len = 0, dec_len = 0;

        auto* data_copy = new uint8_t[data_len];
        memcpy(data_copy, plain.data(), data_len);

        CipherContext ctx(cipher, key, modes[i], Padding::PKCS7, 16,
                          modes[i] != Mode::ECB ? iv : nullptr, {1});

        uint8_t* encrypted = ctx.encrypt(data_copy, data_len, enc_len);
        uint8_t* decrypted = ctx.decrypt(encrypted, enc_len, dec_len);

        bool match = (dec_len == data_len) && (memcmp(plain.data(), decrypted, data_len) == 0);
        std::cout << "  " << mode_names[i] << " -> " << (match ? "OK" : "FAIL") << std::endl;

        delete[] data_copy;
        delete[] encrypted;
        delete[] decrypted;
    }
    delete cipher;
    std::cout << std::endl;
}

int main()
{
    std::cout << "============================================" << std::endl;
    std::cout << "    Rijndael (AES) Demo" << std::endl;
    std::cout << "============================================" << std::endl;

    demoGaloisField();
    demoIrreduciblePolynomials();

    demoRijndael(128, 128);
    demoRijndael(128, 192);
    demoRijndael(128, 256);
    demoRijndael(192, 192);
    demoRijndael(256, 256);

    demoRijndael(128, 128, 0x71);

    demoRijndaelModes();

    std::cout << "Done." << std::endl;
    return 0;
}
