#include "rpc_client.hpp"
#include "logger.hpp"
#include <curl/curl.h>
#include <iostream>
#include <sstream>

// Конструктор
RPC_Client::RPC_Client(const std::string& url, const std::string& user, const std::string& password)
    : rpcUrl(url), rpcUser(user), rpcPassword(password) {}

// Callback для записи ответа от CURL
size_t RPC_Client::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Основной метод отправки запросов
Json RPC_Client::sendRequest(const std::string& method, const Json& params) {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    long http_code = 0;

    curl = curl_easy_init();
    if (curl) {
        Json request;
        request["jsonrpc"] = "1.0";
        request["id"] = "qxspool";
        request["method"] = method;
        request["params"] = params.is_null() ? Json::array() : params;
        
        std::string jsonStr = request.dump();

        // [LOG] Логируем исходящий запрос к ноде (DEBUG уровень)
        // Logger::debug("RPC REQ -> " + method + ": " + jsonStr);

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "content-type: text/plain;");
        
        curl_easy_setopt(curl, CURLOPT_URL, rpcUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonStr.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_USERNAME, rpcUser.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, rpcPassword.c_str());
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L); // Таймаут 30 секунд
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            Logger::error("CURL error: " + std::string(curl_easy_strerror(res)));
            return Json();
        }
    } else {
        Logger::error("Failed to init CURL");
        return Json();
    }

    // [LOG] Логируем ответ от ноды
    // Обрезаем слишком длинные ответы (например getblocktemplate), чтобы не засорять консоль
    if (readBuffer.length() > 1000) {
        Logger::debug("RPC RESP <- (Truncated): " + readBuffer.substr(0, 1000) + "...");
    } else {
        Logger::debug("RPC RESP <- " + readBuffer);
    }

    if (http_code != 200) {
        Logger::error("RPC HTTP Error Code: " + std::to_string(http_code));
        // Пытаемся распарсить ошибку, если она есть в JSON
        try {
            Json errResp = Json::parse(readBuffer);
            if(errResp.contains("error") && !errResp["error"].is_null()) {
                Logger::error("RPC Error Details: " + errResp["error"].dump());
            }
        } catch (...) {}
        return Json();
    }

    try {
        Json response = Json::parse(readBuffer);
        if (response.contains("error") && !response["error"].is_null()) {
            Logger::error("RPC returned error: " + response["error"].dump());
            return Json();
        }
        return response["result"];
    } catch (const std::exception& e) {
        Logger::error("JSON Parse Error: " + std::string(e.what()));
        return Json();
    }
}

// Реализация методов-оберток
Json RPC_Client::getBlockchainInfo() { return sendRequest("getblockchaininfo"); }
Json RPC_Client::getBlockCount() { return sendRequest("getblockcount"); }
Json RPC_Client::getBlockHash(int height) { return sendRequest("getblockhash", buildParams(height)); }

Json RPC_Client::getBlock(const std::string& blockHash, bool verbose) {
    return sendRequest("getblock", buildParams(blockHash, verbose ? 2 : 1));
}

Json RPC_Client::getNetworkInfo() { return sendRequest("getnetworkinfo"); }
Json RPC_Client::uptime() { return sendRequest("uptime"); }

Json RPC_Client::getBlockTemplate(const Json& templateRequest) {
    Json params = Json::array();
    params.push_back(templateRequest);
    return sendRequest("getblocktemplate", params);
}

Json RPC_Client::submitBlock(const std::string& hexData) {
    return sendRequest("submitblock", buildParams(hexData));
}

Json RPC_Client::getNetworkHashPS(int nBlocks, int height) {
    return sendRequest("getnetworkhashps", buildParams(nBlocks, height));
}

Json RPC_Client::getBalance() { return sendRequest("getbalance"); }
Json RPC_Client::validateAddress(const std::string& address) { return sendRequest("validateaddress", buildParams(address)); }
Json RPC_Client::listUnspent(int minconf, int maxconf) { return sendRequest("listunspent", buildParams(minconf, maxconf)); }

Json RPC_Client::sendMany(const std::map<std::string, double>& outputs, const std::string& comment) {
    Json outputJson = Json::object();
    for (auto const& [addr, amount] : outputs) {
        outputJson[addr] = amount;
    }
    return sendRequest("sendmany", buildParams("", outputJson, 1, comment));
}