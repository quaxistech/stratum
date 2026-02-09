#include "job_manager.hpp"
#include "utils.hpp"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

std::map<std::string, StratumJob> JobManager::activeJobs;
std::mutex JobManager::jobsMutex;

std::vector<uint8_t> JobManager::sha256d(std::span<const uint8_t> data) {
    uint8_t hash1[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash1);
    uint8_t hash2[SHA256_DIGEST_LENGTH];
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
    return std::vector<uint8_t>(hash2, hash2 + SHA256_DIGEST_LENGTH);
}

std::string JobManager::reverseHash(const std::string& hex) {
    return Utils::swapEndianHex(hex);
}

std::vector<uint8_t> JobManager::hexToBin(const std::string& hex) {
    return Utils::hexToBin(hex);
}

std::string JobManager::binToHex(std::span<const uint8_t> data) {
    return Utils::binToHex(data);
}

std::string JobManager::encodeHeight(int64_t height) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    if (height < 0xfd) {
        ss << std::setw(2) << height;
    } else {
        ss << "fd" << std::setw(4) << height;
    }
    return ss.str();
}

std::vector<std::string> JobManager::buildMerkleSteps(std::span<const std::vector<uint8_t>> txs) {
    std::vector<std::string> hashes;
    for (const auto& tx : txs) {
        auto h = sha256d(tx);
        hashes.push_back(Utils::swapEndianHex(binToHex(h)));
    }
    return hashes;
}

std::string JobManager::calculateMerkleRoot(const std::string& coinbaseHash,
                                            const std::vector<std::string>& branch) {
    std::string current = coinbaseHash;
    for (const auto& b : branch) {
        std::vector<uint8_t> concat;
        auto left = hexToBin(Utils::swapEndianHex(current));
        auto right = hexToBin(Utils::swapEndianHex(b));
        concat.insert(concat.end(), left.begin(), left.end());
        concat.insert(concat.end(), right.begin(), right.end());
        auto h = sha256d(concat);
        current = Utils::swapEndianHex(binToHex(h));
    }
    return current;
}

StratumJob JobManager::processTemplate(const Json& gbt,
                                       uint64_t jobId,
                                       const std::string& payoutScript,
                                       const std::string& versionHex) {
    StratumJob job{};
    job.jobId = std::to_string(jobId);
    job.prevHash = Utils::swapEndianHex(gbt.at("previousblockhash"));
    job.nbits = std::stoul(gbt.at("bits").get<std::string>(), nullptr, 16);
    job.ntime = gbt.at("curtime");
    job.cleanJobs = true;

    job.version = std::stoul(versionHex, nullptr, 16);

    // Coinbase construction
    std::string heightScript = encodeHeight(gbt.at("height").get<int64_t>());

    job.coinbase1 =
        "01000000" +
        "01" +
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "ffffffff" +
        Utils::encodeVarInt(heightScript.size() / 2) +
        heightScript;

    job.coinbase2 =
        "ffffffff" +
        Utils::encodeVarInt(1) +
        Utils::encodeVarInt(payoutScript.size() / 2) +
        payoutScript +
        "00000000";

    // Merkle branches
    job.merkleBranch.clear();
    if (gbt.contains("transactions")) {
        for (const auto& tx : gbt["transactions"]) {
            job.merkleBranch.push_back(tx.at("hash"));
            job.txDataHex.push_back(tx.at("data"));
        }
    }

    return job;
}

void JobManager::addJob(const StratumJob& job) {
    std::lock_guard<std::mutex> lock(jobsMutex);
    activeJobs[job.jobId] = job;
}

ShareResult JobManager::validateShare(const std::string& jobId,
                                      const std::string& extranonce1,
                                      const std::string& extranonce2,
                                      const std::string& ntimeStr,
                                      const std::string& nonceStr,
                                      uint32_t versionMask,
                                      double poolDiff) {
    ShareResult result{};
    result.isValid = false;
    result.isBlockCandidate = false;

    StratumJob job;
    {
        std::lock_guard<std::mutex> lock(jobsMutex);
        if (!activeJobs.contains(jobId)) {
            result.errorReason = "Unknown job";
            return result;
        }
        job = activeJobs[jobId];
    }

    // Version rolling: XOR mask
    uint32_t clientVersion = std::stoul(versionMask ? Utils::uint32ToHex(versionMask) : "0", nullptr, 16);
    uint32_t finalVersion = job.version ^ clientVersion;

    std::string coinbaseHex =
        job.coinbase1 +
        extranonce1 +
        extranonce2 +
        job.coinbase2;

    auto coinbaseBin = hexToBin(coinbaseHex);
    auto coinbaseHash = sha256d(coinbaseBin);
    std::string coinbaseHashHex = Utils::swapEndianHex(binToHex(coinbaseHash));

    std::string merkleRoot = calculateMerkleRoot(coinbaseHashHex, job.merkleBranch);

    std::string headerHex =
        Utils::swapEndianHex(Utils::uint32ToHex(finalVersion)) +
        job.prevHash +
        Utils::swapEndianHex(merkleRoot) +
        Utils::swapEndianHex(ntimeStr) +
        Utils::swapEndianHex(Utils::uint32ToHex(job.nbits)) +
        Utils::swapEndianHex(nonceStr);

    auto headerBin = hexToBin(headerHex);
    auto hash = sha256d(headerBin);
    std::string hashHexBE = binToHex(hash);
    std::string hashHexLE = Utils::swapEndianHex(hashHexBE);

    result.blockHash = hashHexLE;

    std::string targetHex = Utils::diffToTarget(poolDiff);
    if (hashHexLE > targetHex) {
        result.errorReason = "Low difficulty share";
        return result;
    }

    result.isValid = true;
    result.difficulty = Utils::targetToDifficulty(targetHex);

    // Network target check
    std::string networkTarget = Utils::swapEndianHex(Utils::uint32ToHex(job.nbits)) + std::string(56, '0');
    if (hashHexLE <= networkTarget) {
        result.isBlockCandidate = true;

        // Build full block
        std::string txCountHex = Utils::encodeVarInt(job.txDataHex.size() + 1);
        std::string blockHex =
            Utils::swapEndianHex(Utils::uint32ToHex(finalVersion)) +
            job.prevHash +
            Utils::swapEndianHex(merkleRoot) +
            Utils::swapEndianHex(ntimeStr) +
            Utils::swapEndianHex(Utils::uint32ToHex(job.nbits)) +
            Utils::swapEndianHex(nonceStr) +
            txCountHex +
            coinbaseHex;

        for (const auto& tx : job.txDataHex)
            blockHex += tx;

        result.blockHex = blockHex;
    }

    return result;
}
