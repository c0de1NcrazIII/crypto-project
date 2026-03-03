#pragma once
#include <cstdint>

class KeySchedule
{
public:
    virtual ~KeySchedule() = default;
    virtual void expandKey(const uint8_t* key, uint8_t* new_keys, uint32_t key_len) = 0;
};

class RoundFunction
{
public:
    virtual ~RoundFunction() = default;
    virtual void roundFun(uint8_t* text, uint8_t* result, uint8_t* roundKey) = 0;
};
