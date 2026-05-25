#include <algorithm>
#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>

#include "domain_config.hpp"
#include "log_server.hpp"
#include "lru_cache.hpp"
#include "proxy_server.hpp"

#define PROXY_PORT  8080
#define LOG_PORT    8081
#define CONFIG_FILE "proxy.conf"

namespace asio = boost::asio;

// ─────────────────────────────────────────────────────────────────────────────
//  Точка входа.
//
//  Поднимает три подсистемы поверх общего io_context:
//    1. LogServer  — WebSocket для веб-панели мониторинга (порт 8081).
//    2. ProxyServer — собственно HTTPS/HTTP прокси (порт 8080).
//    3. LRUCache    — общий потокобезопасный кэш ответов, разделяемый
//                     всеми сессиями через shared_ptr.
//
//  Аргумент: число worker-потоков, выполняющих ioc.run().
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: server <threads>\n";
        return EXIT_FAILURE;
    }

    auto const threads = std::max<int>(1, std::atoi(argv[1]));
    asio::io_context ioc{threads};

    // ── WebSocket-сервер для веб-панели ──────────────────────────────────────
    LogServer::init(ioc, LOG_PORT);
    std::cout << "[SERVER] Веб-панель: открой panel.html в браузере\n";

    // ── Загрузка конфигурации доменов (tunnel / mitm списки) ─────────────────
    auto config = DomainConfig::load(CONFIG_FILE);

    // ── Запуск прокси-сервера ────────────────────────────────────────────────
    auto global_cache = std::make_shared<LRUCache>(1000);
    std::make_shared<ProxyServer>(ioc, PROXY_PORT, global_cache, config)->do_accept();
    std::cout << "[SERVER] Прокси слушает на порту " << PROXY_PORT << "\n";

    // ── Обработка SIGINT / SIGTERM для корректного завершения ────────────────
    asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&ioc](boost::system::error_code const& ec, int) {
        if (!ec) {
            std::cout << "\n[SERVER] Остановка...\n";
            ioc.stop();
        }
    });

    // ── Запуск worker-потоков ────────────────────────────────────────────────
    // Главный поток сам тоже выполняет ioc.run(), поэтому создаём (threads-1)
    // дополнительных потоков.
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

    // Освобождаем LogServer (и его tcp::acceptor) до уничтожения io_context.
    // Иначе static shared_ptr переживает ioc, и TSan ловит heap-use-after-free
    // внутри reactive_socket_service::destroy().
    LogServer::shutdown();

    return EXIT_SUCCESS;
}
