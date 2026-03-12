# Требуем минимум CMake 3.16 для поддержки предварительно скомпилированных заголовков
cmake_minimum_required(VERSION 3.16)

project(BoostAsioProxy LANGUAGES CXX)


find_package(Boost REQUIRED COMPONENTS system)
# Поиск OpenSSL
find_package(OpenSSL REQUIRED)



# Добавляем наш исполняемый файл
add_executable(server chat_server.cpp lru_cache.h)

target_compile_features(server PUBLIC cxx_std_17)

target_include_directories(server PUBLIC 
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