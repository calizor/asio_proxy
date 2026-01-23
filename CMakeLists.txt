cmake_minimum_required(VERSION 3.10)
project(BoostAsioProxy)

# Стандарт C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Поиск Boost (Asio обычно требует System и Date_Time)
find_package(Boost REQUIRED COMPONENTS system date_time beast json)

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    add_executable(server chat_server.cpp)
    
    # Линковка Boost и системных библиотек Windows для сокетов (ws2_32 и mswsock)
    target_link_libraries(server
        PRIVATE 
        Boost::system 
        Boost::beast
        Boost::json
        ws2_32 
        mswsock
    )

   
else()
    message(FATAL_ERROR "Boost не найден! Проверьте установку в MSYS2.")
endif()
