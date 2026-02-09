#pragma once

#include <string>
#include <memory>
#include <atomic>
#include <boost/asio.hpp>

#include "config.hpp"
#include "rpc_client.hpp"
#include "zmq_client.hpp"
#include "stratum_server.hpp"
#include "job_manager.hpp"

class PoolEngine {
public:
    // Теперь принимаем io_context и Config
    PoolEngine(boost::asio::io_context& io, const Config& cfg);
    void run();
    // Метод, который вызовет StratumServer
    ShareResult processShare(const std::string& jobId, 
                             const std::string& en1, 
                             const std::string& en2, 
                             const std::string& ntime, 
                             const std::string& nonce);
                             
    void submitBlockToNetwork(const std::string& blockHex);
    const Config& getConfig() const { return config_; }

private:
    void update_job(bool clean_jobs);
    void start_periodic_update();

    boost::asio::io_context& io_context_;
    const Config& config_; // Ссылка на настройки
    RPC_Client rpc_;
    ZMQ_Client zmq_;
    StratumServer stratum_;
    std::unique_ptr<boost::asio::steady_timer> timer_;
    std::atomic<uint64_t> job_counter_;
    JobManager jobManager_; // Теперь это член класса, а не локальная переменная!
};