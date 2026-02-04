cmake_minimum_required(VERSION 3.20)
project(stratum_server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

find_package(Boost REQUIRED COMPONENTS system)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(stratum_server
  src/main.cpp
)

target_link_libraries(stratum_server
  PRIVATE
    Boost::system
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

install(TARGETS stratum_server RUNTIME DESTINATION bin)
