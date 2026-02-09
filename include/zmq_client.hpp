#pragma once

#include <zmq.hpp>
#include <string>
#include <thread>
#include <functional>
#include <boost/asio.hpp>
#include "logger.hpp"

class ZMQ_Client {
public:
    using NewBlockCallback = std::function<void(const std::string& blockHash)>;

    // Добавляем io_context в конструктор
    ZMQ_Client(boost::asio::io_context& io, const std::string& host, int port);
    ~ZMQ_Client();

    void start(NewBlockCallback callback);
    void stop();

private:
    boost::asio::io_context& io_context_;
    std::string endpoint;
    zmq::context_t context;
    std::atomic<bool> running; // Используем атомарный флаг для потокобезопасности
    std::thread workerThread;

    void run_loop(NewBlockCallback callback);
};