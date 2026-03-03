#pragma once
#include "feistel/KeySchedule.h"
#include "des/DesCipher.h"

namespace deal_constants {
    inline uint64_t R_CONST = 0x0123456789ABCDEF;
    inline uint8_t DEAL_IV[8] = {0, 0, 0, 0, 0, 0, 0, 0};
}

class DealKeySchedule final : public KeySchedule
{
    void expandKey(const uint8_t* key, uint8_t* new_keys, uint32_t key_len) override
    {
        const auto K_1 = reinterpret_cast<const uint64_t*>(key);
        const auto K_2 = K_1 + 1;
        auto des = new DesCipher();
        uint8_t* des_key = reinterpret_cast<uint8_t*>(&deal_constants::R_CONST);
        uint64_t t = 0;

        if (key_len == 128) {
            t = *K_1 ^ *reinterpret_cast<uint64_t*>(deal_constants::DEAL_IV);
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys, des_key);
            t = *K_2 ^ *reinterpret_cast<uint64_t*>(new_keys);
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 8, des_key);
            uint64_t i = (1ULL << 63);
            t = *K_1 ^ *reinterpret_cast<uint64_t*>(new_keys + 8) ^ i;
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 16, des_key);
            i = (1ULL << 62);
            t = *K_2 ^ *reinterpret_cast<uint64_t*>(new_keys + 16) ^ i;
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 24, des_key);
            i = (1ULL << 60);
            t = *K_1 ^ *reinterpret_cast<uint64_t*>(new_keys + 24) ^ i;
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 32, des_key);
            i = (1ULL << 56);
            t = *K_2 ^ *reinterpret_cast<uint64_t*>(new_keys + 32) ^ i;
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 40, des_key);
        } else if (key_len == 192) {
            const auto K_3 = K_1 + 2;
            t = *K_1 ^ *reinterpret_cast<uint64_t*>(deal_constants::DEAL_IV);
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys, des_key);
            t = *K_2 ^ *reinterpret_cast<uint64_t*>(new_keys);
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 8, des_key);
            t = *K_3 ^ *reinterpret_cast<uint64_t*>(new_keys + 8);
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 16, des_key);
            uint64_t i = (1ULL << 63);
            t = *K_2 ^ *reinterpret_cast<uint64_t*>(new_keys + 16) ^ i;
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 24, des_key);
            i = (1ULL << 62);
            t = *K_1 ^ *reinterpret_cast<uint64_t*>(new_keys + 24) ^ i;
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 32, des_key);
            i = (1ULL << 60);
            t = *K_2 ^ *reinterpret_cast<uint64_t*>(new_keys + 32) ^ i;
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 40, des_key);
        } else if (key_len == 256) {
            const auto K_3 = K_1 + 2;
            const auto K_4 = K_1 + 3;
            t = *K_1 ^ *reinterpret_cast<uint64_t*>(deal_constants::DEAL_IV);
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys, des_key);
            t = *K_2 ^ *reinterpret_cast<uint64_t*>(new_keys);
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 8, des_key);
            t = *K_3 ^ *reinterpret_cast<uint64_t*>(new_keys + 8);
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 16, des_key);
            t = *K_4 ^ *reinterpret_cast<uint64_t*>(new_keys + 16);
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 24, des_key);
            uint64_t i = (1ULL << 63);
            t = *K_1 ^ *reinterpret_cast<uint64_t*>(new_keys + 24) ^ i;
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 32, des_key);
            i = (1ULL << 62);
            t = *K_2 ^ *reinterpret_cast<uint64_t*>(new_keys + 32) ^ i;
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 40, des_key);
            i = (1ULL << 60);
            t = *K_3 ^ *reinterpret_cast<uint64_t*>(new_keys + 40) ^ i;
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 48, des_key);
            i = (1ULL << 56);
            t = *K_4 ^ *reinterpret_cast<uint64_t*>(new_keys + 48) ^ i;
            des->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 56, des_key);
        }
        delete des;
    }
};
