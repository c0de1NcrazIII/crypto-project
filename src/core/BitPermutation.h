#pragma once
#include <cstdint>
#include <cstddef>

enum class ByteOrder { BigEndian, LittleEndian };

uint8_t get_bit(const uint8_t* text, size_t ind, size_t size_text, ByteOrder order);
void set_bit(uint8_t* text, size_t new_ind, uint8_t bit, size_t size_text, ByteOrder order);
void permutations(const uint8_t* block, size_t size_block,
                  const int* p_block, size_t size_p, uint8_t* new_block,
                  ByteOrder order = ByteOrder::BigEndian, bool is_indexing_from_zero = false);
