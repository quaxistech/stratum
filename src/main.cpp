#include <iostream>
#include <boost/asio.hpp>
#include "config.hpp"
#include "logger.hpp"
#include "pool_engine.hpp"

int main() {
    try {
        Logger::info("=== QXSPool Stratum Server Starting ===");

        // 1. Загружаем конфиг (ищет config.json в текущем каталоге)
        Config cfg = Config::load("config.json");
        Logger::info("Configuration loaded successfully");

        // 2. Создаем ОДИН io_context
        boost::asio::io_context io_context;

        // 3. Инициализируем PoolEngine, передавая ему конфиг и контекст
        // PoolEngine внутри сам создаст RPC_Client и StratumServer, используя данные из cfg
        PoolEngine engine(io_context, cfg);

        Logger::info("Pool Engine initialized. Starting server on port " + std::to_string(cfg.port));

        // 4. Запускаем цикл обработки событий
        engine.run(); // Если у тебя есть метод start, или просто io_context.run()
        io_context.run();

    } catch (const std::exception& e) {
        Logger::error("CRITICAL ERROR in main: " + std::string(e.what()));
        return 1;
    }
    return 0;
}