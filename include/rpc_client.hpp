#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

using Json = nlohmann::json;

class RPC_Client {
public:
    // ИСПРАВЛЕНО: URL теперь идет первым аргументом, чтобы совпадать с PoolEngine
    RPC_Client(const std::string& url, const std::string& user, const std::string& password);
    ~RPC_Client() = default;

    // Основной метод запроса
    Json sendRequest(const std::string& method, const Json& params = Json::array());

    // --- Блокчейн ---
    Json getBlockchainInfo();
    Json getBlockCount();
    Json getBlockHash(int height);
    Json getBlock(const std::string& blockHash, bool verbose = true);
    Json getNetworkInfo();
    Json uptime();

    // --- Майнинг ---
    Json getBlockTemplate(const Json& templateRequest = Json::object());
    Json submitBlock(const std::string& hexData);
    Json getNetworkHashPS(int nBlocks = 120, int height = -1);

    // --- Кошелек ---
    Json getBalance();
    Json validateAddress(const std::string& address);
    Json listUnspent(int minconf = 1, int maxconf = 9999999);
    Json sendMany(const std::map<std::string, double>& outputs, const std::string& comment = "");

private:
    std::string rpcUrl;
    std::string rpcUser;
    std::string rpcPassword;

    // Вспомогательная функция для записи ответа CURL
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
    
    // Помощник для создания JSON параметров
    template<typename... Args>
    Json buildParams(Args&&... args) {
        Json params = Json::array();
        (params.push_back(std::forward<Args>(args)), ...);
        return params;
    }
};