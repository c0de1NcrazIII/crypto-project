#include <iostream>
#include <iomanip>
#include <cstring>

#include "idea/IdeaCipher.h"
#include "modes/CipherContext.h"

static void printHex(const uint8_t* data, size_t len, const char* label)
{
    std::cout << label << ": ";
    for (size_t i = 0; i < len; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    std::cout << std::dec << std::endl;
}

static void demoIdeaBlock()
{
    std::cout << "=== IDEA Block Cipher ===" << std::endl;

    uint8_t plaintext[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t encrypted[8] = {};
    uint8_t decrypted[8] = {};

    IdeaCipher idea;

    printHex(plaintext, 8, "Plaintext ");
    printHex(key, 16, "Key       ");

    idea.encrypt(plaintext, encrypted, key);
    printHex(encrypted, 8, "Encrypted ");

    idea.decrypt(encrypted, decrypted, key);
    printHex(decrypted, 8, "Decrypted ");

    std::cout << "Match: " << (memcmp(plaintext, decrypted, 8) == 0 ? "YES" : "NO") << std::endl;
    std::cout << std::endl;

    // Test with all-zeros
    uint8_t zero_plain[8] = {0};
    uint8_t zero_key[16]  = {0};
    uint8_t zero_enc[8] = {};
    uint8_t zero_dec[8] = {};

    idea.encrypt(zero_plain, zero_enc, zero_key);
    idea.decrypt(zero_enc, zero_dec, zero_key);

    printHex(zero_plain, 8, "Plaintext (zeros)");
    printHex(zero_enc, 8,   "Encrypted        ");
    printHex(zero_dec, 8,   "Decrypted        ");
    std::cout << "Match: " << (memcmp(zero_plain, zero_dec, 8) == 0 ? "YES" : "NO") << std::endl;
    std::cout << std::endl;
}

static void demoIdeaModes()
{
    std::cout << "=== IDEA with Cipher Modes ===" << std::endl;

    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t iv[8] = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};

    std::string plain = "IDEA (International Data Encryption Algorithm) test with cipher modes!";
    auto* data = reinterpret_cast<uint8_t*>(plain.data());
    uint64_t data_len = plain.size();

    const char* mode_names[] = {"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "RandomDelta"};
    Mode modes[] = {Mode::ECB, Mode::CBC, Mode::PCBC, Mode::CFB, Mode::OFB, Mode::CTR, Mode::RandomDelta};
    Padding pads[] = {Padding::ZEROS, Padding::PKCS7};
    const char* pad_names[] = {"ZEROS", "PKCS7"};

    auto* idea = new IdeaCipher();

    for (int m = 0; m < 7; m++) {
        for (int p = 0; p < 2; p++) {
            uint64_t enc_len = 0, dec_len = 0;

            auto* data_copy = new uint8_t[data_len];
            memcpy(data_copy, plain.data(), data_len);

            CipherContext ctx(idea, key, modes[m], pads[p], 8,
                              modes[m] != Mode::ECB ? iv : nullptr, {1});

            uint8_t* encrypted = ctx.encrypt(data_copy, data_len, enc_len);
            uint8_t* decrypted = ctx.decrypt(encrypted, enc_len, dec_len);

            bool match = (dec_len == data_len) && (memcmp(plain.data(), decrypted, data_len) == 0);
            std::cout << "  " << mode_names[m] << "/" << pad_names[p]
                      << " -> " << (match ? "OK" : "FAIL") << std::endl;

            delete[] data_copy;
            delete[] encrypted;
            delete[] decrypted;
        }
    }
    delete idea;
    std::cout << std::endl;
}

int main()
{
    std::cout << "============================================" << std::endl;
    std::cout << "    IDEA Cipher Demo" << std::endl;
    std::cout << "============================================" << std::endl;

    demoIdeaBlock();
    demoIdeaModes();

    std::cout << "Done." << std::endl;
    return 0;
}
