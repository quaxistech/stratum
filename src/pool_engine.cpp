#include "pool_engine.hpp"
#include <iostream>

PoolEngine::PoolEngine(boost::asio::io_context& io, const Config& cfg)
    : io_context_(io),
      config_(cfg),
      rpc_(cfg.rpc_url, cfg.rpc_user, cfg.rpc_password),
      zmq_(cfg.zmq_block_host, cfg.zmq_block_port),
      stratum_(io, cfg.port, *this),
      job_counter_(0) {}

void PoolEngine::run() {
    start_periodic_update();
    stratum_.startAccept();
}

void PoolEngine::start_periodic_update() {
    timer_ = std::make_unique<boost::asio::steady_timer>(io_context_, std::chrono::seconds(config_.poll_interval));
    timer_->async_wait([this](const boost::system::error_code& ec) {
        if (!ec) {
            update_job(false);
            start_periodic_update();
        }
    });
}

void PoolEngine::update_job(bool force_clean) {
    Json gbt = rpc_.call("getblocktemplate", Json::array());

    std::string prevHash = gbt.at("previousblockhash");
    bool clean = force_clean || (prevHash != current_prev_hash_);
    current_prev_hash_ = prevHash;

    uint64_t jobId = ++job_counter_;
    auto job = jobManager_.processTemplate(
        gbt,
        jobId,
        config_.payout_address_script,
        config_.getVersionHexLE()
    );
    job.cleanJobs = clean;
    jobManager_.addJob(job);
    stratum_.broadcastJob(job);
}

ShareResult PoolEngine::processShare(const std::string& jobId,
                                     const std::string& en1,
                                     const std::string& en2,
                                     const std::string& ntime,
                                     const std::string& nonce,
                                     uint32_t versionMask) {
    auto res = jobManager_.validateShare(jobId, en1, en2, ntime, nonce, versionMask, currentDifficulty());
    if (res.isBlockCandidate) {
        submitBlockToNetwork(res.blockHex);
    }
    return res;
}

void PoolEngine::submitBlockToNetwork(const std::string& blockHex) {
    Json params = Json::array({ blockHex });
    rpc_.call("submitblock", params);
}
