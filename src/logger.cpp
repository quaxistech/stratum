#include "logger.hpp"

std::mutex Logger::logMutex;

void Logger::error(const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::cerr << "\033[1;31m[ERROR]\033[0m " << message << std::endl;
}

void Logger::info(const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::cout << "\033[1;32m[INFO]\033[0m " << message << std::endl;
}

// Новый метод для подробных логов
void Logger::debug(const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);
    // Используем желтый цвет для дебага
    std::cout << "\033[1;33m[DEBUG]\033[0m " << message << std::endl;
}

void Logger::json(const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::cout << "\033[1;36m[JSON]\033[0m " << message << std::endl;
}