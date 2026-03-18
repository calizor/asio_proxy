#pragma once

#include <boost/asio.hpp>
#include <memory>
#include "proxy_session.hpp" 
#include "lru_cache.hpp"

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

class ProxyServer : public std::enable_shared_from_this<ProxyServer> {
    tcp::acceptor acceptor_;
    std::shared_ptr<LRUCache> cache_;
public:
    ProxyServer(asio::io_context& ctx, unsigned short port, std::shared_ptr<LRUCache> cache)
        : acceptor_(ctx, {tcp::v4(), port}), cache_(std::move(cache)) {}

    void do_accept() {
        auto session_strand = asio::make_strand(acceptor_.get_executor());
        acceptor_.async_accept(session_strand,
            [self = shared_from_this()](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    // Создаем новую сессию и запускаем её
                    std::make_shared<ProxySession>(std::move(socket), self->cache_)->start();
                }
                self->do_accept();
            });
    }
};