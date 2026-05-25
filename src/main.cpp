#include <algorithm>
#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>

#include "domain_config.hpp"
#include "lru_cache.hpp"
#include "proxy_server.hpp"
#include "log_server.hpp"

#define PROXY_PORT   8080
#define LOG_PORT     8081
#define CONFIG_FILE  "proxy.conf"

namespace asio = boost::asio;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: server <threads>\n";
        return EXIT_FAILURE;
    }

    auto const threads = std::max<int>(1, std::atoi(argv[1]));
    asio::io_context ioc{threads};

    // ── Запускаем WebSocket-сервер для веб-панели ──
    LogServer::init(ioc, LOG_PORT);
    std::cout << "[SERVER] Веб-панель: открой panel.html в браузере\n";

    // ── Загружаем конфигурацию доменов ──
    auto config = DomainConfig::load(CONFIG_FILE);

    // ── Запускаем прокси ──
    auto global_cache = std::make_shared<LRUCache>(1000);
    std::make_shared<ProxyServer>(ioc, PROXY_PORT, global_cache, config)->do_accept();
    std::cout << "[SERVER] Прокси слушает на порту " << PROXY_PORT << "\n";

    asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&ioc](boost::system::error_code const& ec, int) {
        if (!ec) {
            std::cout << "\n[SERVER] Остановка...\n";
            ioc.stop();
        }
    });

    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for (auto i = threads - 1; i > 0; --i)
        v.emplace_back([&ioc, i] {
            std::cout << "Thread " << i << " started\n";
            ioc.run();
        });

    std::cout << "Main thread running\n";
    ioc.run();

    for (auto& t : v)
        if (t.joinable()) t.join();

    // Release LogServer (and its tcp::acceptor) before ioc is destroyed.
    // Without this the static shared_ptr outlives ioc and TSan reports
    // heap-use-after-free inside reactive_socket_service::destroy().
    LogServer::shutdown();

    return EXIT_SUCCESS;
}
