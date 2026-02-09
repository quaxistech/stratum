#pragma once

#include <string>
#include <vector>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <nlohmann/json.hpp>

using Json = nlohmann::json;

struct MergedChain {
    std::string name;
    std::string ticker;
    std::string rpc_url;
    std::string rpc_user;
    std::string rpc_password;
    std::string payout_address;
    bool enabled;
};

struct Config {
    // RPC Settings
    std::string rpc_url;
    std::string rpc_user;
    std::string rpc_password;

    // ZMQ Settings (Для мгновенного получения новых блоков)
    std::string zmq_block_host;
    uint16_t zmq_block_port;

    // Network Settings
    std::string bind_address;
    uint16_t port;
    int poll_interval;
    double default_difficulty;
    
    // Mining Settings
    std::string payout_address_script; // "00146463e..."
    uint32_t protocol_version;         // 1073733632
    int extranonce1_size;
    int extranonce2_size;

    // Merged Mining
    std::vector<MergedChain> merged_chains;

    // Конвертация protocol_version (Big Endian) в Little Endian Hex
    // 0x3fffe000 (1073733632) -> "00e0ff3f"
    std::string getVersionHexLE() const {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        ss << std::setw(2) << (protocol_version & 0xFF);
        ss << std::setw(2) << ((protocol_version >> 8) & 0xFF);
        ss << std::setw(2) << ((protocol_version >> 16) & 0xFF);
        ss << std::setw(2) << ((protocol_version >> 24) & 0xFF);
        return ss.str();
    }

    static Config load(const std::string& filename = "config.json") {
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Could not find " + filename + " in current directory!");
        }

        Json j;
        file >> j;

        Config cfg;
        
        // RPC
        cfg.rpc_url = j.at("rpc_url");
        cfg.rpc_user = j.at("rpc_user");
        cfg.rpc_password = j.at("rpc_password");

        // ZMQ
        cfg.zmq_block_host = j.value("zmq_block_host", "127.0.0.1");
        cfg.zmq_block_port = j.value("zmq_block_port", 28332);

        // Network
        cfg.bind_address = j.value("bind_address", "0.0.0.0");
        cfg.port = j.at("port");
        cfg.poll_interval = j.value("poll_interval_seconds", 5);
        cfg.default_difficulty = j.value("default_difficulty", 32.0);
        
        // Mining
        cfg.payout_address_script = j.at("payout_address");
        cfg.extranonce1_size = j.value("extranonce1_size", 4);
        cfg.extranonce2_size = j.value("extranonce2_size", 8);

        // Protocol Version
        if (j.contains("protocol_version")) {
            if (j["protocol_version"].is_number()) {
                cfg.protocol_version = j["protocol_version"].get<uint32_t>();
            } else if (j["protocol_version"].is_string()) {
                // Если в конфиге строка "0x3fffe000", конвертируем корректно
                cfg.protocol_version = std::stoul(j["protocol_version"].get<std::string>(), nullptr, 0);
            }
        } else {
            cfg.protocol_version = 2; // Default
        }

        // Merged Mining
        if (j.contains("merged_mining_chains")) {
            for (auto& item : j["merged_mining_chains"]) {
                if (item.value("enabled", false)) {
                    cfg.merged_chains.push_back({
                        item.at("name"),
                        item.at("ticker"),
                        item.at("rpc_url"),
                        item.at("rpc_user"),
                        item.at("rpc_password"),
                        item.at("payout_address"),
                        true
                    });
                }
            }
        }
        return cfg;
    }
};