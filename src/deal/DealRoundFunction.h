#pragma once
#include "feistel/KeySchedule.h"
#include "des/DesCipher.h"

class DealRoundFunction : public RoundFunction
{
    void roundFun(uint8_t* text, uint8_t* result, uint8_t* roundKey) override
    {
        auto alg = DesCipher();
        alg.encrypt(text, result, roundKey);
    }
};
