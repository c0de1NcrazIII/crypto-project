#pragma once

#include <any>
#include <chrono>
#include <iostream>
#include <vector>
#include <cstring>
#include <fstream>
#include <random>
#include <thread>

#include "core/BitPermutation.h"
#include "core/BlockCipher.h"

enum class Mode { ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta };

enum class Padding { ZEROS, ANSI_X923, PKCS7, ISO10126 };

class   CipherContext
{
    BlockCipher* algorithm;
    uint8_t* key;
    Mode mode;
    Padding padding;
    const uint64_t block_size;
    uint8_t* iv = nullptr;
    std::vector<std::any> additional = {};

public:

    CipherContext(BlockCipher* _algorithm,
                  uint8_t* _key,
                  Mode _mode, Padding _padding,
                  uint64_t _block_size,
                  uint8_t* _iv = nullptr,
                  std::initializer_list<std::any> _additional = {}) :
            algorithm(_algorithm), key(_key), mode(_mode), padding(_padding), block_size(_block_size), iv(_iv), additional(_additional){}

    void paddingLastBlock(const uint8_t* data, const uint64_t size, uint8_t* last_block) const
    {
        const uint64_t rest = size % block_size;

        memcpy(last_block, data + size - rest, rest);

        switch (padding)
        {
            case Padding::ZEROS:
            {
                break;
            }
            case Padding::PKCS7:
            {
                for (auto i = rest; i < block_size; i++)
                {
                    last_block[i] = block_size - rest;
                }
                break;
            }
            case Padding::ANSI_X923:
            {
                last_block[block_size - 1] = block_size - rest;
                break;
            }
            case Padding::ISO10126:
            {
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<uint8_t> dist(0, 255);
                for (int i = rest; i < block_size - 1; i++)
                {
                    last_block[i] = dist(gen);
                }
                last_block[block_size - 1] = block_size - rest;
                break;
            }
            default:
                printf("Something went wrong (padding last block)");
                break;
        }

    }

    void unpaddingLastBlock(const uint8_t* last_block, const uint64_t rest, uint8_t* output) const
    {
        if (padding != Padding::ZEROS && last_block[block_size - 1] != block_size - rest)
        {
            std::cerr << "padding last block does not match" << std::endl;
        }
        memcpy(output, last_block, rest);
    }

    static void XOR(uint8_t* res, const uint8_t* first, const uint8_t* second, const uint64_t block_size)
    {
        for (uint64_t i = 0; i < block_size; i++)
        {
            if (res == first) {
                res[i] ^= second[i];
            } else
            {
                res[i] = first[i] ^ second[i];
            }
        }
    }

    static void threadEncr(const CipherContext* context, uint8_t* data,
                           const uint64_t ind_thread, const uint64_t num_of_threads,
                           const uint64_t num_of_blocks, uint8_t* output)
    {
        for (uint64_t i = 0; i * num_of_threads + ind_thread < num_of_blocks; ++i)
        {
            uint64_t ind_of_block = i * num_of_threads + ind_thread;

            context->algorithm->encrypt(data + ind_of_block * context->block_size,
                                        output + ind_of_block * context->block_size, context->key);
        }
    }

    static void thread_delta_encr(const CipherContext* context, uint8_t* data, uint8_t* output, const uint8_t* iv,
                                  const uint64_t ind_thread, const uint64_t num_of_threads, const uint64_t num_of_blocks, const uint32_t delta)
    {
        uint8_t tmp_iv[context->block_size];
        memcpy(tmp_iv + sizeof(uint64_t),
               iv + sizeof(uint64_t), context->block_size - sizeof(uint64_t));

        for (uint64_t j = 0; j * num_of_threads + ind_thread < num_of_blocks; ++j)
        {
            const uint64_t ind_of_block = j * num_of_threads + ind_thread;

            *reinterpret_cast<uint64_t*>(tmp_iv) = *(uint64_t*)(iv) + ind_of_block * delta;
            context->algorithm->encrypt(tmp_iv,
                                        output + ind_of_block * context->block_size, context->key);
            XOR(output + ind_of_block * context->block_size,
                output + ind_of_block * context->block_size,
                data + ind_of_block * context->block_size, context->block_size);
        }
    }

    static void thread_delta_decr(const CipherContext* context, uint8_t* data, uint8_t* output, const uint8_t* iv,
                                  const uint64_t ind_thread, const uint64_t num_of_threads, const uint64_t num_of_blocks, const uint32_t delta)
    {
        uint8_t tmp_iv[context->block_size];
        memcpy(tmp_iv + sizeof(uint64_t),
               iv + sizeof(uint64_t), context->block_size - sizeof(uint64_t));

        for (uint64_t j = 0; j * num_of_threads + ind_thread < num_of_blocks; ++j)
        {
            const uint64_t ind_of_block = j * num_of_threads + ind_thread;

            *reinterpret_cast<uint64_t*>(tmp_iv) = *(uint64_t*)(iv) + ind_of_block * delta;
            context->algorithm->encrypt(tmp_iv,
                                        output + ind_of_block * context->block_size, context->key);
            XOR(output + ind_of_block * context->block_size,
                output + ind_of_block * context->block_size,
                data + ind_of_block * context->block_size, context->block_size);
        }
    }

    uint8_t* encrypt(uint8_t* data, const uint64_t size, uint64_t& output_len) const
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dist(0, 255);

        uint64_t block_count = size / block_size;
        const uint64_t rest = size % block_size;

        output_len = (block_count + 1 + (rest != 0) + (mode == Mode::RandomDelta)) * block_size;
        auto output = new uint8_t[output_len]();

        uint8_t service_block[block_size];
        service_block[0] = rest;

        for (int i = 1; i < block_size; i++)
        {
            service_block[i] = dist(gen);
        }

        switch (mode)
        {
            case Mode::ECB:
            {
                algorithm->encrypt(service_block, output + (block_count + (rest != 0)) * block_size, key);

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back(threadEncr,
                                         this, data, i, num_of_threads, block_count, output);
                }
                for (auto& t : threads)
                {
                    t.join();
                }

                if (rest != 0) {
                    std::vector<uint8_t> last_block(block_size, 0);
                    paddingLastBlock(data, size, last_block.data());
                    algorithm->encrypt(last_block.data(), output + block_count * block_size, key);
                }

                return output;
            }
            case Mode::CBC:
            {
                auto tmp_iv = reinterpret_cast<uint64_t*>(iv);
                auto tmp_text = reinterpret_cast<uint64_t*>(service_block);
                *tmp_text ^= *tmp_iv;
                algorithm->encrypt(service_block, output, key);


                for (uint64_t i = 0; i < block_count; ++i)
                {
                    tmp_text = reinterpret_cast<uint64_t*>(data + i * block_size);
                    tmp_iv = reinterpret_cast<uint64_t*>(output + i * block_size);
                    *tmp_text ^= *tmp_iv;
                    algorithm->encrypt(data + i * block_size,
                                       output + (i + 1) * block_size, key);
                }

                if (rest != 0) {
                    std::vector<uint8_t> last_block(block_size, 0);
                    paddingLastBlock(data, size, last_block.data());

                    tmp_text = reinterpret_cast<uint64_t*>(last_block.data());
                    tmp_iv = reinterpret_cast<uint64_t*>(output + block_count * block_size);
                    *tmp_text ^= *tmp_iv;
                    algorithm->encrypt(last_block.data(), output + (block_count + 1) * block_size, key);
                }

                return output;
            }
            case Mode::PCBC:
            {
                uint8_t tmp_text[block_size];

                XOR(tmp_text, service_block, iv, block_size);

                algorithm->encrypt(tmp_text, output, key);

                for (uint64_t i = 0; i < block_count; ++i)
                {
                    XOR(tmp_text, data + i * block_size, output + i * block_size, block_size); // m2 ^ c1
                    if (i == 0)
                    {
                        XOR(tmp_text, tmp_text, service_block, block_size);
                    } else
                    {
                        XOR(tmp_text, tmp_text, data + (i - 1) * block_size, block_size); // ^ m1
                    }

                    algorithm->encrypt(tmp_text, output + (i + 1) * block_size, key);
                }

                if (rest != 0) {
                    std::vector<uint8_t> last_block(block_size, 0);
                    paddingLastBlock(data, size, last_block.data());

                    XOR(tmp_text, last_block.data(), output + block_count * block_size, block_size);
                    XOR(tmp_text, tmp_text, data + (block_count - 1) * block_size, block_size);

                    algorithm->encrypt(tmp_text, output + (block_count + 1) * block_size, key);
                }

                return output;
            }
            case Mode::CFB:
            {
                algorithm->encrypt(iv, output, key);

                XOR(output, output, service_block, block_size);

                for (uint64_t i = 0; i < block_count; ++i)
                {
                    algorithm->encrypt(output + i * block_size,
                                       output + (i + 1) * block_size, key);

                    XOR(output + (i + 1) * block_size,
                        output + (i + 1) * block_size, data + i * block_size, block_size);
                }

                if (rest != 0) {
                    std::vector<uint8_t> last_block(block_size, 0);
                    paddingLastBlock(data, size, last_block.data());
                    algorithm->encrypt(output + block_count * block_size,
                                       output + (block_count + 1) * block_size, key);
                    XOR(output + (block_count + 1) * block_size,
                        output + (block_count + 1) * block_size, last_block.data(), block_size);
                }

                return output;
            }
            case Mode::OFB:
            {
                std::vector<uint8_t> tmp_iv(block_size, 0);

                algorithm->encrypt(iv, tmp_iv.data(), key);

                XOR(output, tmp_iv.data(), service_block, block_size);


                for (uint64_t i = 0; i < block_count; ++i)
                {
                    algorithm->encrypt(tmp_iv.data(), tmp_iv.data(), key);

                    XOR(output + (i + 1) * block_size,
                        tmp_iv.data(), data + i * block_size, block_size);
                }

                if (rest != 0) {
                    std::vector<uint8_t> last_block(block_size, 0);
                    paddingLastBlock(data, size, last_block.data());

                    algorithm->encrypt(tmp_iv.data(), tmp_iv.data(), key);
                    XOR(output + (block_count + 1) * block_size, tmp_iv.data(), last_block.data(), block_size);
                }

                return output;
            }
            case Mode::CTR:
            {
                uint8_t tmp_iv[block_size];
                memcpy(tmp_iv + sizeof(uint64_t),
                       iv + sizeof(uint64_t), block_size - sizeof(uint64_t));
                *reinterpret_cast<uint64_t*>(tmp_iv) =
                        *reinterpret_cast<uint64_t*>(iv) + block_count + (rest != 0);

                algorithm->encrypt(tmp_iv, output + (block_count + (rest != 0)) * block_size, key);
                XOR(output + (block_count + (rest != 0)) * block_size,
                    output + (block_count + (rest != 0)) * block_size,
                    service_block, block_size);

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back(thread_delta_encr, this, data, output, iv,
                                         i, num_of_threads, block_count, 1);
                }
                for (auto& t : threads)
                {
                    t.join();
                }

                if (rest != 0) {
                    std::vector<uint8_t> last_block(block_size, 0);
                    paddingLastBlock(data, size, last_block.data());

                    *reinterpret_cast<uint64_t*>(tmp_iv) =
                            *reinterpret_cast<uint64_t*>(this->iv) + block_count;
                    algorithm->encrypt(tmp_iv, output + block_count * block_size, key);

                    XOR(output + block_count * block_size,
                        output + block_count * block_size, last_block.data(), block_size);
                }

                return output;
            }
            case Mode::RandomDelta:
            {
                uint8_t rnd_iv[block_size];

                for (size_t i = 0; i < block_size; ++i) {
                    rnd_iv[i] = dist(gen);
                }
                uint32_t delta = *reinterpret_cast<uint32_t*>(rnd_iv);

                algorithm->encrypt(rnd_iv, output, key);

                uint8_t tmp_iv[block_size];
                memcpy(tmp_iv + sizeof(uint64_t),
                       rnd_iv + sizeof(uint64_t), block_size - sizeof(uint64_t));
                *reinterpret_cast<uint64_t*>(tmp_iv) =
                        *reinterpret_cast<uint64_t*>(rnd_iv) + (block_count + (rest != 0)) * delta;

                algorithm->encrypt(tmp_iv,
                                   output + (block_count + 1 + (rest != 0)) * block_size, key);
                XOR(output + (block_count + 1 + (rest != 0)) * block_size,
                    output + (block_count + 1 + (rest != 0)) * block_size, service_block, block_size);

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back(thread_delta_encr, this, data, output + block_size, static_cast<uint8_t*>(rnd_iv),
                                         i, num_of_threads, block_count, delta);
                }
                for (auto& t : threads)
                {
                    t.join();
                }

                if (rest != 0) {
                    std::vector<uint8_t> last_block(block_size, 0);
                    paddingLastBlock(data, size, last_block.data());

                    *reinterpret_cast<uint64_t*>(tmp_iv) = *reinterpret_cast<uint64_t*>(rnd_iv) + block_count * delta;
                    algorithm->encrypt(tmp_iv,
                                       output + (block_count + 1) * block_size, key);

                    XOR(output + (block_count + 1) * block_size,
                        output + (block_count + 1) * block_size,
                        last_block.data(), block_size);
                }

                return output;
            }

            default:
                printf("Something went wrong (encryption)");
                break;
        }
        return nullptr;
    }

    uint8_t* decrypt(uint8_t* data, const uint64_t size, uint64_t& output_len) const
    {
        uint64_t block_count = size / block_size;
        std::vector<uint8_t> service_block(block_size, 0);

        switch (mode)
        {
            case Mode::ECB:
            {
                algorithm->decrypt(data + (block_count - 1) * block_size, service_block.data(), key);

                const uint64_t rest = service_block[0];
                block_count -= 1 + (rest != 0);

                output_len = block_count * block_size + rest;
                auto output = new uint8_t[output_len]();

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back([this, data, i, num_of_threads, block_count, output]
                                         {
                                             for (uint64_t j = 0; j * num_of_threads + i < block_count; ++j)
                                             {
                                                 uint64_t ind_of_block = j * num_of_threads + i;

                                                 this->algorithm->decrypt(data + ind_of_block * this->block_size,
                                                                          output + ind_of_block * this->block_size, this->key);
                                             }
                                         });
                }
                for (auto& t : threads)
                {
                    t.join();
                }

                if (rest) {
                    std::vector<uint8_t> last_block(block_size, 0);
                    algorithm->decrypt(data + block_count * block_size, last_block.data(), key);

                    unpaddingLastBlock(last_block.data(), rest, output + block_count * block_size);
                }

                return output;
            }
            case Mode::CBC:
            {
                algorithm->decrypt(data, service_block.data(), key);
                auto tmp_iv = reinterpret_cast<uint64_t*>(iv);
                auto tmp_text = reinterpret_cast<uint64_t*>(service_block.data());
                *tmp_text ^= *tmp_iv;

                const uint64_t rest = service_block[0];
                block_count -= 1 + (rest != 0);

                output_len = block_count * block_size + rest;
                auto output = new uint8_t[output_len]();

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back([this, data, i, num_of_threads, block_count, output]
                                         {
                                             for (uint64_t j = 0; j * num_of_threads + i < block_count; ++j)
                                             {
                                                 uint64_t ind_of_block = j * num_of_threads + i;

                                                 this->algorithm->decrypt(data + (ind_of_block + 1) * this->block_size,
                                                                          output + ind_of_block * this->block_size, this->key);

                                                 const auto tmp_iv_loc = reinterpret_cast<uint64_t*>(data + ind_of_block * this->block_size);
                                                 const auto tmp_text_loc = reinterpret_cast<uint64_t*>(output + ind_of_block * this->block_size);
                                                 *tmp_text_loc = (*tmp_text_loc) ^ (*tmp_iv_loc);
                                             }
                                         });
                }
                for (auto& t : threads)
                {
                    t.join();
                }

                if (rest) {
                    std::vector<uint8_t> last_block(block_size, 0);
                    algorithm->decrypt(data + (block_count + 1) * block_size, last_block.data(), key);
                    tmp_iv = reinterpret_cast<uint64_t*>(data + block_count * block_size);
                    tmp_text = reinterpret_cast<uint64_t*>(last_block.data());
                    *tmp_text ^= *tmp_iv;

                    unpaddingLastBlock(last_block.data(), rest, output + block_count * block_size);
                }

                return output;
            }
            case Mode::PCBC:
            {
                algorithm->decrypt(data, service_block.data(), key);

                XOR(service_block.data(), service_block.data(), iv, block_size);

                const uint64_t rest = service_block[0];
                block_count -= 1 + (rest != 0);

                output_len = block_count * block_size + rest;
                auto output = new uint8_t[output_len]();

                for (uint64_t i = 0; i < block_count; ++i)
                {
                    algorithm->decrypt(data + (i + 1) * block_size,
                                       output + i * block_size, key);

                    XOR(output + i * block_size, output + i * block_size,
                        data + i * block_size, block_size); // m2 ^ c1
                    if (i == 0)
                    {
                        XOR(output + i * block_size, output + i * block_size,
                            service_block.data(), block_size);
                    } else
                    {
                        XOR(output + i * block_size, output + i * block_size,
                            output + (i - 1) * block_size, block_size); // ^ m1
                    }
                }

                if (rest) {
                    std::vector<uint8_t> last_block(block_size, 0);
                    algorithm->decrypt(data + (block_count + 1) * block_size, last_block.data(), key);

                    XOR(last_block.data(), last_block.data(), data + block_count * block_size, block_size);
                    XOR(last_block.data(), last_block.data(), output + (block_count - 1) * block_size, block_size);

                    unpaddingLastBlock(last_block.data(), rest, output + block_count * block_size);
                }

                return output;
            }
            case Mode::CFB:
            {
                algorithm->encrypt(iv, service_block.data(), key);

                XOR(service_block.data(), service_block.data(), data, block_size);

                const uint64_t rest = service_block[0];
                block_count -= 1 + (rest != 0);

                output_len = block_count * block_size + rest;
                auto output = new uint8_t[output_len]();

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back([this, data, i, num_of_threads, block_count, output]
                                         {
                                             for (uint64_t j = 0; j * num_of_threads + i < block_count; ++j)
                                             {
                                                 uint64_t ind_of_block = j * num_of_threads + i;

                                                 this->algorithm->encrypt(data + ind_of_block * this->block_size,
                                                                          output + ind_of_block * this->block_size, this->key);
                                                 XOR(output + ind_of_block * this->block_size,
                                                     output + ind_of_block * this->block_size,
                                                     data + (ind_of_block + 1) * this->block_size, this->block_size);
                                             }
                                         });
                }
                for (auto& t : threads)
                {
                    t.join();
                }

                if (rest) {
                    std::vector<uint8_t> last_block(block_size, 0);

                    algorithm->encrypt(data + block_count * block_size,
                                       last_block.data(), key);
                    XOR(last_block.data(), last_block.data(), data + (block_count + 1) * block_size, block_size);

                    unpaddingLastBlock(last_block.data(), rest, output + block_count * block_size);
                }

                return output;
            }
            case Mode::OFB:
            {
                std::vector<uint8_t> tmp_iv(block_size, 0);
                algorithm->encrypt(iv, tmp_iv.data(), key);

                XOR(service_block.data(), tmp_iv.data(), data, block_size);

                const uint64_t rest = service_block[0];
                block_count -= 1 + (rest != 0);

                output_len = block_count * block_size + rest;
                auto output = new uint8_t[output_len]();

                for (uint64_t i = 0; i < block_count; ++i)
                {
                    algorithm->encrypt(tmp_iv.data(), tmp_iv.data(), key);
                    XOR(output + i * block_size,
                        tmp_iv.data(), data + (i + 1) * block_size, block_size);
                }

                if (rest) {
                    std::vector<uint8_t> last_block(block_size, 0);

                    algorithm->encrypt(tmp_iv.data(), tmp_iv.data(), key);
                    XOR(last_block.data(), tmp_iv.data(), data + (block_count + 1) * block_size, block_size);

                    unpaddingLastBlock(last_block.data(), rest, output + block_count * block_size);
                }

                return output;
            }
            case Mode::CTR:
            {
                uint8_t tmp_iv[block_size];
                memcpy(tmp_iv + sizeof(uint64_t),
                       iv + sizeof(uint64_t), block_size - sizeof(uint64_t));
                *reinterpret_cast<uint64_t*>(tmp_iv) =
                        *reinterpret_cast<uint64_t*>(this->iv) + block_count - 1;

                algorithm->encrypt(tmp_iv, service_block.data(), key);
                XOR(service_block.data(), service_block.data(),
                    data + (block_count - 1) * block_size, block_size);

                const uint64_t rest = service_block[0];
                block_count -= 1 + (rest != 0);

                output_len = block_count * block_size + rest;
                auto output = new uint8_t[output_len]();

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back(thread_delta_decr, this, data, output, iv,
                                         i, num_of_threads, block_count, 1);
                }
                for (auto& t : threads)
                {
                    t.join();
                }

                if (rest != 0) {
                    std::vector<uint8_t> last_block(block_size, 0);

                    *reinterpret_cast<uint64_t*>(tmp_iv) = *reinterpret_cast<uint64_t*>(this->iv) + block_count;
                    algorithm->encrypt(tmp_iv, last_block.data(), key);
                    XOR(last_block.data(), last_block.data(),
                        data + block_count * block_size, block_size);

                    unpaddingLastBlock(last_block.data(), rest, output + block_count * block_size);
                }

                return output;
            }
            case Mode::RandomDelta:
            {
                std::vector<uint8_t> rnd_iv(block_size, 0);
                algorithm->decrypt(data, rnd_iv.data(), key);

                uint32_t delta = *reinterpret_cast<uint32_t*>(rnd_iv.data());
                --block_count;

                std::vector<uint8_t> tmp_iv(block_size);

                memcpy(tmp_iv.data() + sizeof(uint64_t),
                       rnd_iv.data() + sizeof(uint64_t), block_size - sizeof(uint64_t));
                *reinterpret_cast<uint64_t*>(tmp_iv.data()) =
                        *reinterpret_cast<uint64_t*>(rnd_iv.data()) + (block_count - 1) * delta;

                algorithm->encrypt(tmp_iv.data(), service_block.data(), key);

                XOR(service_block.data(), service_block.data(), data + block_count * block_size, block_size);

                const uint64_t rest = service_block[0];
                block_count -= 1 + (rest != 0);

                output_len = block_count * block_size + rest;
                auto output = new uint8_t[output_len]();

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back(thread_delta_decr, this, data + block_size, output, static_cast<uint8_t*>(rnd_iv.data()),
                                         i, num_of_threads, block_count, delta);
                }
                for (auto& t : threads)
                {
                    t.join();
                }

                if (rest != 0) {
                    std::vector<uint8_t> last_block(block_size, 0);

                    *reinterpret_cast<uint64_t*>(tmp_iv.data()) =
                            *reinterpret_cast<uint64_t*>(rnd_iv.data()) + block_count * delta;
                    algorithm->encrypt(tmp_iv.data(), last_block.data(), key);
                    XOR(last_block.data(), last_block.data(),
                        data + (block_count + 1) * block_size, block_size);

                    unpaddingLastBlock(last_block.data(), rest, output + block_count * block_size);
                }

                return output;
            }

            default:
                printf("Something went wrong (decryption)");
                break;
        }
        return nullptr;
    }

    void encrypt(const std::string& inputPath, const std::string& outputPath) const
    {
        if (inputPath == outputPath)
        {
            std::cout << "The input file shouldn`t match the output file." << std::endl;
            return;
        }

        std::ifstream in(inputPath, std::ios::binary);
        std::ofstream out(outputPath, std::ios::binary);

        if (!in.is_open()) {
            std::cout << "File opening error: " << inputPath << std::endl;
            return;
        }
        if (!out.is_open()) {
            std::cout << "File opening error: " << outputPath << std::endl;
            in.close();
            return;
        }

        constexpr size_t BLOCK_SIZE = 24576;
        uint8_t buffer[BLOCK_SIZE];

        while (in) {
            in.read(reinterpret_cast<char*>(buffer), BLOCK_SIZE);
            std::streamsize bytes_read = in.gcount();

            if (bytes_read > 0) {
                uint64_t out_len = 0;
                uint8_t* enc = encrypt(buffer, bytes_read, out_len);

                out.write(reinterpret_cast<char*>(enc), out_len);
                delete[] enc;
            }
        }
        in.close();
        out.close();
    }
    void decrypt(const std::string& inputPath, const std::string& outputPath) const
    {
        if (inputPath == outputPath)
        {
            std::cout << "The input file shouldn`t match the output file." << std::endl;
            return;
        }

        std::ifstream in(inputPath, std::ios::binary);
        std::ofstream out(outputPath, std::ios::binary);

        if (!in.is_open()) {
            std::cout << "File opening error: " << inputPath << std::endl;
            return;
        }
        if (!out.is_open()) {
            std::cout << "File opening error: " << outputPath << std::endl;
            in.close();
            return;
        }


        const size_t BLOCK_SIZE = 24576 + block_size * (1 + (mode == Mode::RandomDelta));
        uint8_t buffer[BLOCK_SIZE];

        while (in) {
            in.read(reinterpret_cast<char*>(buffer), BLOCK_SIZE);
            std::streamsize bytes_read = in.gcount();

            if (bytes_read > 0) {
                uint64_t out_len = 0;
                uint8_t* dec = decrypt(buffer, static_cast<uint64_t>(bytes_read), out_len);

                out.write(reinterpret_cast<char*>(dec), out_len);
                delete[] dec;
            }
        }

        in.close();
        out.close();
    }
};