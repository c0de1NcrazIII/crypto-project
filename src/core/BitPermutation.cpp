#include "BitPermutation.h"

uint8_t get_bit(const uint8_t* text, const size_t ind, const size_t size_text, ByteOrder order)
{
    uint8_t bit;
    if (order == ByteOrder::LittleEndian)
        bit = text[(size_text - 1 - ind) / 8] & (1 << (ind % 8));
    else
        bit = text[ind / 8] & (1 << (7 - (ind % 8)));
    return bit > 0;
}

void set_bit(uint8_t* text, const size_t new_ind, uint8_t bit, const size_t size_text, ByteOrder order)
{
    if (order == ByteOrder::LittleEndian)
        text[(size_text - 1 - new_ind) / 8] |= bit << (new_ind % 8);
    else
        text[new_ind / 8] |= bit << (7 - (new_ind % 8));
}

void permutations(const uint8_t* block, const size_t size_block,
                  const int* p_block, const size_t size_p, uint8_t* new_block,
                  const ByteOrder order, bool is_indexing_from_zero)
{
    for (size_t i = 0; i < size_p; i++)
    {
        const uint8_t bit = get_bit(block, p_block[i] - (is_indexing_from_zero ? 0 : 1),
                                    size_block, order);
        set_bit(new_block, i, bit, size_p, order);
    }
}
