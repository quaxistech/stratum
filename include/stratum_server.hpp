#pragma once

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <memory>
#include <set>
#include <mutex>
#include <string>
#include <iostream>

#include "job_manager.hpp" // Содержит StratumJob и ShareResult
#include "config.hpp"      // Содержит структуру Config

using boost::asio::ip::tcp;
using json = nlohmann::json;

// Forward declaration, чтобы избежать циклической зависимости.
// StratumServer знает, что существует класс PoolEngine, но его полное определение
// будет доступно только в .cpp файле.
class PoolEngine;
class StratumServer;

/**
 * @brief Представляет одно соединение с майнером (TCP сессия).
 */
class StratumSession : public std::enable_shared_from_this<StratumSession> {
public:
    StratumSession(tcp::socket socket, uint32_t sessionId, StratumServer& server);

    void start();
    void sendJob(const StratumJob& job);

private:
    void readRequest();
    void handleRequest(const std::string& data);
    
    // Обработка отправки шары (mining.submit)
    void processSubmit(const json& params, const json& id);

    // Вспомогательные методы отправки ответов
    void sendResponse(const json& id, const json& result, const json& error);
    void sendError(const json& id, int code, const std::string& message);
    void sendJson(const json& j);

    tcp::socket socket_;
    boost::asio::streambuf buffer_;
    
    uint32_t sessionId_;
    StratumServer& server_;
    
    std::string extranonce1_;
    
    bool authorized_;
    bool subscribed_;
};

/**
 * @brief Основной класс сервера Stratum V1.
 * Принимает соединения и управляет сессиями.
 */
class StratumServer {
public:
    // Конструктор принимает ссылку на Engine для взаимодействия с глобальной логикой
    StratumServer(boost::asio::io_context& io_context, uint16_t port, PoolEngine& engine);

    // Рассылка нового задания всем подключенным майнерам
    void broadcastJob(const StratumJob& job);
    
    // Удаление отключившейся сессии
    void removeSession(const std::shared_ptr<StratumSession>& session);

    // --- Методы-прокси к PoolEngine (вызываются из сессии) ---
    
    // Проверка шары
    ShareResult submitShare(const std::string& jobId, 
                            const std::string& en1, 
                            const std::string& en2, 
                            const std::string& ntime, 
                            const std::string& nonce);
                            
    // Обработка найденного блока (отправка в сеть)
    void processFoundBlock(const std::string& blockHex);

    // Получение конфигурации (для extranonce2_size и т.д.)
    const Config& getConfig() const;
    
    // Получение текущей сложности пула
    double currentDifficulty() const;

private:
    void startAccept();

    tcp::acceptor acceptor_;
    PoolEngine& engine_; // Ссылка на главный класс движка
    
    std::mutex sessionsMutex_;
    std::set<std::shared_ptr<StratumSession>> sessions_;
    
    uint32_t nextSessionId_;
};