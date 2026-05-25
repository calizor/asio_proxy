#pragma once

#include <boost/asio.hpp>
#include <memory>

#include "connection_handler.hpp"
#include "domain_config.hpp"
#include "lru_cache.hpp"

namespace asio = boost::asio;
using tcp      = asio::ip::tcp;

// ─────────────────────────────────────────────────────────────────────────────
//  ProxyServer — корневой accept-loop прокси.
//
//  Слушает указанный TCP-порт, и на каждое входящее соединение создаёт
//  ConnectionHandler. Кэш и конфиг передаются всем соединениям через
//  shared_ptr.
//
//  do_accept() запускает рекурсивный async_accept: после обработки одного
//  соединения немедленно ставит следующий accept в очередь.
// ─────────────────────────────────────────────────────────────────────────────
class ProxyServer : public std::enable_shared_from_this<ProxyServer> {
    tcp::acceptor                 acceptor_;
    std::shared_ptr<LRUCache>     cache_;
    std::shared_ptr<DomainConfig> config_;

   public:
    ProxyServer(asio::io_context&             ctx,
                unsigned short                port,
                std::shared_ptr<LRUCache>     cache,
                std::shared_ptr<DomainConfig> config)
        : acceptor_(ctx, {tcp::v4(), port}),
          cache_(std::move(cache)),
          config_(std::move(config)) {}

    // Принимает новое соединение и сразу же ставит в очередь следующий accept.
    // Каждое соединение получает собственный strand — это нужно для корректной
    // работы при числе потоков > 1: все колбэки сессии будут сериализованы.
    void do_accept() {
        auto session_strand = asio::make_strand(acceptor_.get_executor());
        acceptor_.async_accept(
            session_strand,
            [self = shared_from_this()](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<ConnectionHandler>(
                        std::move(socket), self->cache_, self->config_)->start();
                }
                self->do_accept();  // продолжаем accept-loop
            });
    }
};
