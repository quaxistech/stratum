#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <span>

using Json = nlohmann::json;

struct StratumJob {
    std::string jobId;
    std::string prevHash;
    std::string coinbase1;
    std::string coinbase2;
    std::vector<std::string> merkleBranch;
    uint32_t version;
    uint32_t nbits;
    uint32_t ntime;
    bool cleanJobs;
    
    // Новое поле: сырые транзакции для сборки блока (кроме coinbase)
    std::vector<std::string> txDataHex; 
};

struct ShareResult {
    bool isValid;
    bool isBlockCandidate;
    std::string blockHex;     // Полный блок для отправки
    std::string blockHash;    // Хеш блока
    double difficulty;        // Сложность шары
    std::string errorReason;
};

class JobManager {
public:
    // ... (старые методы)
    static std::vector<uint8_t> sha256d(std::span<const uint8_t> data);
    static std::string reverseHash(const std::string& hex);
    
    StratumJob processTemplate(const Json& gbt, uint64_t jobId, const std::string& payoutScript, const std::string& versionHex);

    // Главный метод проверки
    ShareResult validateShare(const std::string& jobId, 
                              const std::string& extranonce1, 
                              const std::string& extranonce2, 
                              const std::string& ntimeStr, 
                              const std::string& nonceStr,
                              double poolDiff);

    // Управление хранилищем работ
    void addJob(const StratumJob& job);
    static std::string binToHex(std::span<const uint8_t> data);
    std::vector<std::string> buildMerkleSteps(std::span<const std::vector<uint8_t>> txs);
    
private:
    // static std::vector<std::string> buildMerkleTree(const std::vector<std::string>& txHashes);
    static std::string encodeHeight(int64_t height);
    static std::vector<uint8_t> hexToBin(const std::string& hex);
   // static std::string binToHex(std::span<const uint8_t> data);
    
    // Helpers
    std::string calculateMerkleRoot(const std::string& coinbaseHash, const std::vector<std::string>& branch);

    // std::mutex jobsMutex;
    // std::map<std::string, StratumJob> validJobs;
    static std::map<std::string, StratumJob> activeJobs;
    static std::mutex jobsMutex;
};