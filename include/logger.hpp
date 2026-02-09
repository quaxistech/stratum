#pragma once
#include <string>
#include <iostream>
#include <mutex>

class Logger {
public:
    static void error(const std::string& message);
    static void info(const std::string& message);
    static void debug(const std::string& message); // Добавлено
    static void json(const std::string& message);
    
    // Вспомогательный метод для форматирования (упрощенный)
    template<typename... Args>
    static void formattedError(const std::string& fmt, Args... args) {
        error(fmt); // Пока просто пробрасываем, чтобы не тянуть fmt либу
    }
    
    template<typename... Args>
    static void formattedInfo(const std::string& fmt, Args... args) {
        info(fmt);
    }

private:
    static std::mutex logMutex;
};