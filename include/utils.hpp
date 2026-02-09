#pragma once
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstdint>
#include <span>
#include <cstdio>
#include <cmath>
#include <openssl/sha.h>
#include "logger.hpp" // Добавляем для логов внутри утилит

namespace Utils {

// Реальная конвертация Difficulty -> Target String (Hex)
inline std::string diffToTarget(double difficulty) {
    // Базовый таргет (diff=1) для пула (обычно 2^256 / 2^32 - 1, но для stratum используется упрощение)
    // Diff 1 = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    // Мы будем использовать double для деления, затем форматировать обратно в hex.
    
    // Максимальное значение (первые 64 бита таргета diff 1)
    const double max_target_head = 0x00000000FFFF0000; 
    
    double current_target_head = max_target_head / difficulty;
    uint64_t target64 = static_cast<uint64_t>(current_target_head);

    std::stringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << target64;
    
    // Остальные 48 байт (16 char + 48 char = 64 char) заполняем нулями для простоты,
    // так как точность double ограничена, но для stratum share этого достаточно.
    std::string targetHex = ss.str() + "000000000000000000000000000000000000000000000000";
    
    // Logger::debug("Diff: " + std::to_string(difficulty) + " -> Target: " + targetHex);
    return targetHex;
}

inline std::string swapEndianHex(const std::string& hex) {
    std::string res;
    res.reserve(hex.length());
    for (size_t i = 0; i < hex.length(); i += 2) {
        if (i + 1 < hex.length())
            res = hex.substr(i, 2) + res;
    }
    return res;
}

inline std::string uint32ToHex(uint32_t v) {
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << v;
    return ss.str();
}

inline double calculateDifficulty(const std::string& targetHex) {
    if (targetHex.length() != 64) return 0.0;

    // Берем первые 16 символов для оценки
    std::string significant = targetHex.substr(0, 16);
    unsigned long long current_val = std::stoull(significant, nullptr, 16);
    
    if (current_val == 0) return 0.0;
    
    double d64_max = 0x00000000FFFF0000; 
    return d64_max / (double)current_val;
}

// Конвертация nbits в сложность сети
static double nbitsToDifficulty(uint32_t nbits) {
    uint32_t shift = (nbits >> 24) & 0xff;
    double diff = (double)0x0000ffff / (double)(nbits & 0x00ffffff);
    while (shift < 29) { diff *= 256.0; shift++; }
    while (shift > 29) { diff /= 256.0; shift--; }
    return diff;
}

}