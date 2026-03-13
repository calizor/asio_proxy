#include <boost/asio.hpp>
#include <iostream>
#include <thread>
#include <vector>
#include <cstdlib>
#include <algorithm>

#include "proxy_server.h" // Подключаем только сервер!

namespace asio = boost::asio;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: server <threads>\n" ;
        return EXIT_FAILURE;
    }
    
    auto const threads = std::max<int>(1, std::atoi(argv[1]));
    asio::io_context ioc{threads};

    // Запускаем сервер на порту 8080
    std::make_shared<ProxyServer>(ioc, 8080)->do_accept();

    // Создаем пул потоков
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for(auto i = threads - 1; i > 0; --i) {
        v.emplace_back([&ioc, i] {
            std::cout << "Thread " << i << " is running\n";
            ioc.run();
        });
    }

    std::cout << "Main thread is running\n";
    ioc.run();

    // Корректное завершение потоков, только до сюда не доходит, ioc.run() бесконечный до ioc.stop()(наверное);
    for (auto& t : v) {
        if (t.joinable()) t.join(); 
    }

    return EXIT_SUCCESS;
}