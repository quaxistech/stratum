#include "stratum_server.hpp"
#include "pool_engine.hpp"
#include <random>

StratumServer::StratumServer(boost::asio::io_context& io_context, uint16_t port, PoolEngine& engine)
    : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
      engine_(engine),
      nextSessionId_(1) {}

void StratumServer::startAccept() {
    acceptor_.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
        if (!ec) {
            auto session = std::make_shared<StratumSession>(std::move(socket), nextSessionId_++, *this);
            {
                std::lock_guard<std::mutex> lock(sessionsMutex_);
                sessions_.insert(session);
            }
            session->start();
        }
        startAccept();
    });
}

void StratumServer::broadcastJob(const StratumJob& job) {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    for (auto& s : sessions_) {
        s->sendJob(job);
    }
}

void StratumServer::removeSession(const std::shared_ptr<StratumSession>& session) {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    sessions_.erase(session);
}

ShareResult StratumServer::submitShare(const std::string& jobId,
                                       const std::string& en1,
                                       const std::string& en2,
                                       const std::string& ntime,
                                       const std::string& nonce,
                                       uint32_t versionMask) {
    return engine_.processShare(jobId, en1, en2, ntime, nonce, versionMask);
}

void StratumServer::processFoundBlock(const std::string& blockHex) {
    engine_.submitBlockToNetwork(blockHex);
}

const Config& StratumServer::getConfig() const {
    return engine_.getConfig();
}

double StratumServer::currentDifficulty() const {
    return engine_.currentDifficulty();
}

// ---------------- Session ----------------

StratumSession::StratumSession(tcp::socket socket, uint32_t sessionId, StratumServer& server)
    : socket_(std::move(socket)),
      sessionId_(sessionId),
      server_(server),
      versionMask_(0),
      authorized_(false),
      subscribed_(false) {}

void StratumSession::start() {
    readRequest();
}

void StratumSession::readRequest() {
    auto self = shared_from_this();
    boost::asio::async_read_until(socket_, buffer_, '\n',
        [this, self](boost::system::error_code ec, std::size_t) {
            if (!ec) {
                std::istream is(&buffer_);
                std::string line;
                std::getline(is, line);
                handleRequest(line);
                readRequest();
            } else {
                server_.removeSession(self);
            }
        });
}

void StratumSession::handleRequest(const std::string& data) {
    json req;
    try {
        req = json::parse(data);
    } catch (...) {
        return;
    }

    std::string method = req.value("method", "");
    json params = req.value("params", json::array());
    json id = req.value("id", nullptr);

    if (method == "mining.subscribe") {
        subscribed_ = true;
        extranonce1_ = generateExtranonce1();

        json result = json::array({
            json::array({
                json::array({"mining.set_difficulty", "1"}),
                json::array({"mining.notify", "1"})
            }),
            extranonce1_,
            server_.getConfig().extranonce2_size
        });

        sendResponse(id, result, nullptr);
        return;
    }

    if (method == "mining.authorize") {
        authorized_ = true;
        sendResponse(id, true, nullptr);
        return;
    }

    if (method == "mining.configure") {
        // Version rolling negotiation
        for (const auto& cap : params[0]) {
            if (cap == "version-rolling") {
                if (params[1].contains("version-rolling.mask")) {
                    versionMask_ = std::stoul(params[1]["version-rolling.mask"].get<std::string>(), nullptr, 16);
                }
            }
        }
        json result = {
            {"version-rolling", true},
            {"version-rolling.mask", Utils::uint32ToHex(versionMask_)}
        };
        sendResponse(id, result, nullptr);
        return;
    }

    if (method == "mining.submit") {
        processSubmit(params, id);
        return;
    }
}

void StratumSession::processSubmit(const json& params, const json& id) {
    if (params.size() < 5) {
        sendError(id, -1, "Invalid submit");
        return;
    }

    std::string jobId = params[1];
    std::string en2 = params[2];
    std::string ntime = params[3];
    std::string nonce = params[4];

    auto res = server_.submitShare(jobId, extranonce1_, en2, ntime, nonce, versionMask_);
    if (!res.isValid) {
        sendError(id, 23, res.errorReason);
        return;
    }

    sendResponse(id, true, nullptr);

    if (res.isBlockCandidate) {
        server_.processFoundBlock(res.blockHex);
    }
}

void StratumSession::sendJob(const StratumJob& job) {
    json params = json::array({
        job.jobId,
        job.prevHash,
        job.coinbase1,
        job.coinbase2,
        job.merkleBranch,
        Utils::swapEndianHex(Utils::uint32ToHex(job.version)),
        Utils::swapEndianHex(Utils::uint32ToHex(job.nbits)),
        Utils::swapEndianHex(Utils::uint32ToHex(job.ntime)),
        job.cleanJobs
    });

    json msg = {
        {"id", nullptr},
        {"method", "mining.notify"},
        {"params", params}
    };

    sendJson(msg);
}

void StratumSession::sendResponse(const json& id, const json& result, const json& error) {
    json resp = {
        {"id", id},
        {"result", result},
        {"error", error}
    };
    sendJson(resp);
}

void StratumSession::sendError(const json& id, int code, const std::string& message) {
    json err = json::array({ code, message, nullptr });
    sendResponse(id, nullptr, err);
}

void StratumSession::sendJson(const json& j) {
    auto self = shared_from_this();
    std::string data = j.dump() + "\n";
    boost::asio::async_write(socket_, boost::asio::buffer(data),
        [this, self](boost::system::error_code ec, std::size_t) {
            if (ec) {
                server_.removeSession(self);
            }
        });
}

std::string StratumSession::generateExtranonce1() {
    std::stringstream ss;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis;
    uint32_t r = dis(gen);
    ss << std::hex << std::setw(8) << std::setfill('0') << r;
    return ss.str();
}
