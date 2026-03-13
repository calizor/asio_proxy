# Требуем минимум CMake 3.16 для поддержки предварительно скомпилированных заголовков
cmake_minimum_required(VERSION 3.16)

project(BoostAsioProxy LANGUAGES CXX)



find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)



add_executable(server 
    src/chat_server.cpp 
    src/proxy_server.h 
    src/proxy_session.h 
    src/cert_manager.h
)

target_compile_features(server PUBLIC cxx_std_17)
    
    # 2. Указываем компилятору, где искать заголовочные файлы
target_include_directories(server PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/src  
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)


target_precompile_headers(server PRIVATE 
    <boost/asio.hpp>
    <boost/beast.hpp>
    <boost/json.hpp> 
)


target_link_libraries(server PRIVATE 
    Boost::system 
    OpenSSL::SSL 
    OpenSSL::Crypto
    $<$<PLATFORM_ID:Windows>:ws2_32>
    $<$<PLATFORM_ID:Windows>:mswsock>
)