cmake_minimum_required(VERSION 3.15)
project(QXSPool VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 1. Поиск пакетов
find_package(CURL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

# Добавляем Boost (нужен для Asio)
find_package(Boost REQUIRED COMPONENTS system thread)

# Добавляем поддержку многопоточности (pthread)
find_package(Threads REQUIRED)

pkg_check_modules(ZMQ REQUIRED libzmq)

# 2. Определение исходников
# Добавил stratum_server.cpp, так как без него не будет реализации сервера
set(SOURCES
    src/main.cpp
    src/logger.cpp
    src/network.cpp
    src/rpc_client.cpp
    src/zmq_client.cpp
    src/job_manager.cpp
    src/stratum_server.cpp
    src/pool_engine.cpp
)

# 3. Создание исполняемого файла
add_executable(QXSPool ${SOURCES})

# 4. Настройка папок инклудов
# Добавляем Boost_INCLUDE_DIRS, чтобы компилятор видел заголовки asio
target_include_directories(QXSPool PRIVATE 
    include 
    ${ZMQ_INCLUDE_DIRS} 
    ${Boost_INCLUDE_DIRS}
)

# 5. Линковка
target_link_libraries(QXSPool PRIVATE 
    CURL::libcurl 
    nlohmann_json::nlohmann_json 
    OpenSSL::Crypto
    OpenSSL::SSL
    ${ZMQ_LIBRARIES}
    Boost::system
    Boost::thread
    Threads::Threads
)