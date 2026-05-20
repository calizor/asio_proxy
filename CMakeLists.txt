cmake_minimum_required(VERSION 3.30)

project(BoostAsioProxy LANGUAGES CXX)

find_package(Boost    REQUIRED)
find_package(OpenSSL  REQUIRED)
find_package(nlohmann_json REQUIRED)   # apt: nlohmann-json3-dev  |  vcpkg: nlohmann-json


add_executable(server
    src/main.cpp
)

target_compile_features(server PUBLIC cxx_std_17)

target_include_directories(server PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

target_precompile_headers(server PRIVATE
    <boost/asio.hpp>
    <boost/beast.hpp>
    <boost/beast/websocket.hpp>
    <nlohmann/json.hpp>
)

target_link_libraries(server PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

option(SANITIZE "Enable sanitizer (thread, address)" "")
if(SANITIZE)
    target_compile_options(server PRIVATE -fsanitize=${SANITIZE} -fno-omit-frame-pointer)
    target_link_options(server PRIVATE -fsanitize=${SANITIZE})
endif()