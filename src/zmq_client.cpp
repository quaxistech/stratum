#include "zmq_client.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>

ZMQ_Client::ZMQ_Client(boost::asio::io_context& io, const std::string& host, int port) 
    : io_context_(io), 
      endpoint("tcp://" + host + ":" + std::to_string(port)), 
      context(1), 
      running(false) {}

ZMQ_Client::~ZMQ_Client() {
    stop();
}

void ZMQ_Client::start(NewBlockCallback callback) {
    if (running) return;
    running = true;
    workerThread = std::thread(&ZMQ_Client::run_loop, this, callback);
}

void ZMQ_Client::stop() {
    running = false;
    if (workerThread.joinable()) {
        workerThread.join();
    }
}

void ZMQ_Client::run_loop(NewBlockCallback callback) {
    zmq::socket_t subscriber(context, ZMQ_SUB);
    
    try {
        subscriber.connect(endpoint);
        subscriber.set(zmq::sockopt::subscribe, "hashblock");
        
        // Устанавливаем таймаут на recv (1000 мс), чтобы поток мог проверять флаг running
        int timeout = 1000;
        subscriber.set(zmq::sockopt::rcvtimeo, timeout);
        
        Logger::info("ZMQ: Subscriber connected to " + endpoint);
    } catch (const zmq::error_t& e) {
        Logger::error("ZMQ: Connection failed: " + std::string(e.what()));
        return;
    }

    while (running) {
        zmq::message_t topic;
        zmq::message_t body;

        // Ожидаем заголовок (тему)
        auto res = subscriber.recv(topic, zmq::recv_flags::none);
        if (!res) continue; // Если вышел таймаут, просто идем на новую итерацию и проверяем running

        // Ожидаем тело сообщения (хеш блока)
        res = subscriber.recv(body, zmq::recv_flags::none);
        if (!res) continue;

        // Конвертируем бинарный хеш в Hex-строку
        std::stringstream ss;
        const auto* data = static_cast<const unsigned char*>(body.data());
        for (size_t i = 0; i < body.size(); ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        }
        std::string blockHash = ss.str();

        // Пробрасываем вызов колбэка через io_context.post
        // Это гарантирует, что работа с заданиями будет идти в главном потоке ASIO
        io_context_.post([callback, blockHash]() {
            if (callback) {
                callback(blockHash);
            }
        });
    }
    Logger::info("ZMQ: Subscriber thread stopped");
}