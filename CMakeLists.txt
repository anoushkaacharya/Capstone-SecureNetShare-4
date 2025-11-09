cmake_minimum_required(VERSION 3.10)
project(SecureNetShare)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

include_directories(include)

add_executable(server
    src/main_server.cpp
    src/server.cpp
    src/utils.cpp
    src/crypto.cpp
)

target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto pthread)

add_executable(client
    src/main_client.cpp
    src/client.cpp
    src/utils.cpp
    src/crypto.cpp
)

target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto pthread)
