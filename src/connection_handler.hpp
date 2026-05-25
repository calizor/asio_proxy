#pragma once

#include <boost/asio.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <memory>
#include <string>

#include "domain_config.hpp"
#include "log_server.hpp"
#include "lru_cache.hpp"
#include "mitm_session.hpp"
#include "tunnel_session.hpp"

namespace asio = boost::asio;
namespace http = boost::beast::http;
using tcp      = asio::ip::tcp;

// ─────────────────────────────────────────────────────────────────────────────
//  ConnectionHandler — обработчик одного клиентского TCP-соединения до
//  момента, пока не станет ясно, что с ним делать дальше.
//
//  Алгоритм:
//    1. Читает заголовки первого HTTP-запроса (ожидается CONNECT).
//    2. Если это CONNECT — извлекает целевой домен из заголовка Host и
//       по конфигу решает: MITM (расшифровываем TLS и кэшируем) или TUNNEL
//       (просто перекидываем байты в обе стороны без расшифровки).
//    3. Шлёт клиенту "200 Connection Established" и передаёт сокет в
//       соответствующую сессию (MitmSession / TunnelSession).
//
//  Plain-HTTP запросы (без CONNECT) отвечаются как 501 Not Implemented —
//  через MITM-прокси Chrome/Firefox всегда ходят CONNECT'ом для HTTPS,
//  а plain-HTTP проксирование пока не поддерживается.
// ─────────────────────────────────────────────────────────────────────────────
class ConnectionHandler : public std::enable_shared_from_this<ConnectionHandler> {
    tcp::socket                             client_socket_;
    boost::beast::flat_buffer               buffer_;
    http::request_parser<http::string_body> parser_;
    std::shared_ptr<LRUCache>               cache_;
    std::shared_ptr<DomainConfig>           config_;

   public:
    ConnectionHandler(tcp::socket                   socket,
                      std::shared_ptr<LRUCache>     cache,
                      std::shared_ptr<DomainConfig> config)
        : client_socket_(std::move(socket)),
          cache_(std::move(cache)),
          config_(std::move(config)) {}

    // Читает заголовок входящего запроса; после успеха вызывает dispatch().
    void start() {
        auto self = shared_from_this();
        http::async_read_header(
            client_socket_, buffer_, parser_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec) self->dispatch();
                // При ошибке self уйдёт из колбэка → объект уничтожится,
                // сокет закроется в деструкторе.
            });
    }

   private:
    // ── Разбор первого запроса и выбор типа сессии ───────────────────────────
    void dispatch() {
        auto req = parser_.get();

        if (req.method() != http::verb::connect) {
            // Plain HTTP не поддерживаем — отвечаем 501 и закрываем соединение.
            auto self = shared_from_this();
            auto resp = std::make_shared<std::string>(
                "HTTP/1.1 501 Not Implemented\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n");
            asio::async_write(client_socket_, asio::buffer(*resp),
                [self, resp](boost::system::error_code, std::size_t) {
                    boost::system::error_code ec;
                    self->client_socket_.shutdown(tcp::socket::shutdown_both, ec);
                    self->client_socket_.close(ec);
                });
            return;
        }

        // Из заголовка Host вытаскиваем чистое имя домена (отрезаем порт).
        std::string domain = std::string(req[http::field::host]);
        if (size_t pos = domain.find(':'); pos != std::string::npos)
            domain.resize(pos);

        LogServer::instance().log_connect(domain);

        // Решение MITM vs TUNNEL принимает DomainConfig.
        if (is_mitm_domain(domain)) {
            send_connect_ok_then<MitmSession>(std::move(domain));
        } else {
            send_connect_ok_then<TunnelSession>(std::move(domain));
        }
    }

    // ── Отправка "200 Connection Established" и старт нужной сессии ──────────
    // Шаблон по типу сессии — единый код для MITM и TUNNEL. TunnelSession
    // третий параметр (кэш) игнорирует, но сигнатура унифицирована.
    template <typename Session>
    void send_connect_ok_then(std::string domain) {
        auto self     = shared_from_this();
        auto response = std::make_shared<std::string>(
            "HTTP/1.1 200 Connection Established\r\n\r\n");

        asio::async_write(
            client_socket_, asio::buffer(*response),
            [self, response, domain = std::move(domain)](
                boost::system::error_code ec, std::size_t) mutable {
                if (!ec) {
                    std::make_shared<Session>(
                        std::move(self->client_socket_),
                        std::move(domain),
                        self->cache_)->start();
                }
            });
    }

    bool is_mitm_domain(const std::string& domain) {
        return config_->is_mitm(domain);
    }
};
