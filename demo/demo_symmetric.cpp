#include <iostream>
#include <iomanip>
#include <cstring>
#include <fstream>

#include "des/DesCipher.h"
#include "triple_des/TripleDesCipher.h"
#include "deal/DealCipher.h"
#include "modes/CipherContext.h"

static void printHex(const uint8_t* data, size_t len, const char* label)
{
    std::cout << label << ": ";
    for (size_t i = 0; i < len; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    std::cout << std::dec << std::endl;
}

static void testBlockCipher(BlockCipher& cipher, const char* name,
                            uint8_t* plaintext, uint8_t* key, size_t block_size)
{
    std::cout << "\n=== " << name << " ===" << std::endl;
    printHex(plaintext, block_size, "Plaintext ");
    printHex(key, block_size == 8 ? 8 : 16, "Key       ");

    auto* encrypted = new uint8_t[block_size]();
    auto* decrypted = new uint8_t[block_size]();

    cipher.encrypt(plaintext, encrypted, key);
    printHex(encrypted, block_size, "Encrypted ");

    cipher.decrypt(encrypted, decrypted, key);
    printHex(decrypted, block_size, "Decrypted ");

    std::cout << "Match: " << (memcmp(plaintext, decrypted, block_size) == 0 ? "YES" : "NO") << std::endl;

    delete[] encrypted;
    delete[] decrypted;
}

static void testCipherMode(BlockCipher* cipher, const char* name,
                           Mode mode, Padding padding,
                           size_t block_size, uint8_t* key)
{
    const char* mode_names[] = {"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "RandomDelta"};
    const char* pad_names[]  = {"ZEROS", "ANSI_X923", "PKCS7", "ISO10126"};

    std::string plain = "Hello, World! This is a test message for symmetric encryption modes.";
    uint64_t data_len = plain.size();
    auto* data_copy = new uint8_t[data_len];
    memcpy(data_copy, plain.data(), data_len);

    uint8_t iv[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    uint64_t enc_len = 0, dec_len = 0;

    CipherContext ctx(cipher, key, mode, padding, block_size,
                      mode != Mode::ECB ? iv : nullptr, {1});

    uint8_t* encrypted = ctx.encrypt(data_copy, data_len, enc_len);
    uint8_t* decrypted = ctx.decrypt(encrypted, enc_len, dec_len);

    bool match = (dec_len == data_len) && (memcmp(plain.data(), decrypted, data_len) == 0);

    std::cout << "  " << name << " | "
              << mode_names[(int)mode] << " | "
              << pad_names[(int)padding] << " -> "
              << (match ? "OK" : "FAIL") << std::endl;

    delete[] data_copy;
    delete[] encrypted;
    delete[] decrypted;
}

static void testFileEncryption()
{
    std::cout << "\n=== File Encryption (DES-CBC) ===" << std::endl;

    const std::string test_file = "test_input.bin";
    const std::string enc_file  = "test_encrypted.bin";
    const std::string dec_file  = "test_decrypted.bin";

    {
        std::ofstream f(test_file, std::ios::binary);
        std::string content = "This is a test file for symmetric file encryption and decryption.";
        f.write(content.data(), content.size());
    }

    uint8_t key[8]  = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    uint8_t iv[8]   = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};

    auto* des = new DesCipher();
    CipherContext ctx(des, key, Mode::CBC, Padding::PKCS7, 8, iv, {1});

    ctx.encrypt(test_file, enc_file);
    ctx.decrypt(enc_file, dec_file);

    std::ifstream orig(test_file, std::ios::binary);
    std::ifstream decr(dec_file, std::ios::binary);
    std::string orig_content((std::istreambuf_iterator<char>(orig)), std::istreambuf_iterator<char>());
    std::string decr_content((std::istreambuf_iterator<char>(decr)), std::istreambuf_iterator<char>());

    std::cout << "Original size:  " << orig_content.size() << " bytes" << std::endl;
    std::cout << "Decrypted size: " << decr_content.size() << " bytes" << std::endl;
    std::cout << "Match: " << (orig_content == decr_content ? "YES" : "NO") << std::endl;

    std::remove(test_file.c_str());
    std::remove(enc_file.c_str());
    std::remove(dec_file.c_str());
    delete des;
}

int main()
{
    std::cout << "============================================" << std::endl;
    std::cout << "    Symmetric Ciphers Demo" << std::endl;
    std::cout << "============================================" << std::endl;

    // --- DES block test ---
    uint8_t des_plain[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    uint8_t des_key[8]   = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    auto des = DesCipher();
    testBlockCipher(des, "DES", des_plain, des_key, 8);

    // --- 3DES block test (3-key) ---
    uint8_t tdes_key[24] = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
                            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
                            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    auto tdes = TripleDesCipher(3);
    testBlockCipher(tdes, "TripleDES (3-key)", des_plain, tdes_key, 8);

    // --- 3DES block test (2-key) ---
    auto tdes2 = TripleDesCipher(2);
    testBlockCipher(tdes2, "TripleDES (2-key)", des_plain, tdes_key, 8);

    // --- DEAL block test ---
    uint8_t deal_plain[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                              0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t deal_key[16]   = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    auto deal = DealCipher(128);
    testBlockCipher(deal, "DEAL-128", deal_plain, deal_key, 16);

    // --- All modes and paddings with DES ---
    std::cout << "\n=== Cipher Modes & Paddings ===" << std::endl;

    auto* des_ptr = new DesCipher();
    Mode modes[] = {Mode::ECB, Mode::CBC, Mode::PCBC, Mode::CFB, Mode::OFB, Mode::CTR, Mode::RandomDelta};
    Padding pads[] = {Padding::ZEROS, Padding::ANSI_X923, Padding::PKCS7, Padding::ISO10126};

    for (auto m : modes) {
        for (auto p : pads) {
            testCipherMode(des_ptr, "DES", m, p, 8, des_key);
        }
    }
    delete des_ptr;

    // --- Modes with TripleDES ---
    std::cout << "\n--- TripleDES modes ---" << std::endl;
    auto* tdes_ptr = new TripleDesCipher(3);
    for (auto m : {Mode::ECB, Mode::CBC, Mode::CTR}) {
        testCipherMode(tdes_ptr, "3DES", m, Padding::PKCS7, 8, tdes_key);
    }
    delete tdes_ptr;

    // --- Modes with DEAL ---
    std::cout << "\n--- DEAL modes ---" << std::endl;
    auto* deal_ptr = new DealCipher(128);
    for (auto m : {Mode::ECB, Mode::CBC, Mode::CTR}) {
        testCipherMode(deal_ptr, "DEAL", m, Padding::PKCS7, 16, deal_key);
    }
    delete deal_ptr;

    // --- File encryption ---
    testFileEncryption();

    std::cout << "\nDone." << std::endl;
    return 0;
}
