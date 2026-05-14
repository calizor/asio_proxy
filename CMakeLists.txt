cmake_minimum_required(VERSION 3.30)

project(BoostAsioProxy LANGUAGES CXX)

find_package(Boost    REQUIRED)
find_package(OpenSSL  REQUIRED)
find_package(nlohmann_json REQUIRED)   # apt: nlohmann-json3-dev  |  vcpkg: nlohmann-json

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=thread -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_DEBUG   "${CMAKE_C_FLAGS_DEBUG}   -fsanitize=thread -fno-omit-frame-pointer")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=thread")

add_executable(server
    src/main.cpp
    src/proxy_server.hpp
    src/connection_handler.hpp
    src/mitm_session.hpp
    src/tunnel_session.hpp
    src/cert_manager.hpp
    src/lru_cache.hpp
    src/log_server.hpp
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
