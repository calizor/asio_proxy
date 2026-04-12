#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>

#include "cert_manager.hpp"
#include "lru_cache.hpp"

namespace asio = boost::asio;
namespace ssl  = boost::asio::ssl;
namespace http = boost::beast::http;
using tcp      = asio::ip::tcp;

// MitmSession — HTTPS MITM-прокси.
// Получает уже распарсенный домен из ConnectionHandler.
// Выполняет TLS-handshake с браузером (поддельный сертификат),
// затем устанавливает TLS с целевым сервером и проксирует трафик.
//
// Контракт: ConnectionHandler уже отправил "200 Connection Established"
// браузеру перед передачей сокета в этот класс.

class MitmSession : public std::enable_shared_from_this<MitmSession> {
    tcp::socket   client_socket_;
    tcp::socket   target_socket_;
    tcp::resolver resolver_;

    // TLS с браузером (мы — сервер)
    std::optional<ssl::stream<tcp::socket&>> client_ssl_stream_;

    // TLS с целевым сервером (мы — клиент)
    ssl::context target_ssl_ctx_{ssl::context::tls_client};
    std::optional<ssl::stream<tcp::socket&>> target_ssl_stream_;

    boost::beast::flat_buffer client_buffer_;
    boost::beast::flat_buffer target_buffer_;
    std::optional<http::request_parser<http::string_body>> parser_;

    http::request<http::string_body>  current_req_;
    http::response<http::string_body> current_res_;

    std::shared_ptr<LRUCache> cache_;
    std::string cache_key_;
    std::string target_domain_;

    boost::asio::steady_timer deadline_;

   public:
    MitmSession(tcp::socket socket, std::string domain, std::shared_ptr<LRUCache> cache = nullptr)
        : client_socket_(std::move(socket)),
          target_socket_(client_socket_.get_executor()),
          resolver_(client_socket_.get_executor()),
          cache_(std::move(cache)),
          target_domain_(std::move(domain)),
          deadline_(client_socket_.get_executor(), std::chrono::seconds(30)) {
        target_ssl_ctx_.set_default_verify_paths();
    }

    // Точка входа — браузер уже получил 200 от ConnectionHandler
    void start() {
        reset_deadline();
        do_client_handshake();
    }

   private:
    // ---------- Таймер ----------

    void reset_deadline(std::chrono::seconds timeout = std::chrono::seconds(30)) {
        deadline_.expires_after(timeout);
        auto self = shared_from_this();
        deadline_.async_wait([self](boost::system::error_code ec) {
            if (ec == boost::asio::error::operation_aborted)
                return;
            if (!ec) {
                std::cout << "[TIMEOUT] " << self->target_domain_ << "\n";
                self->close();
            }
        });
    }

    // ---------- ШАГ 1: TLS-handshake с браузером ----------

    void do_client_handshake() {
        auto self        = shared_from_this();
        auto session_ctx = CertManager::get_context_for_domain(target_domain_);

        if (!session_ctx) {
            std::cerr << "[MITM] No SSL context for " << target_domain_ << "\n";
            close();
            return;
        }

        client_ssl_stream_.emplace(client_socket_, *session_ctx);
        client_ssl_stream_->async_handshake(
            ssl::stream_base::server,
            [self](boost::system::error_code ec) {
                if (!ec)
                    self->read_client_request();
                else
                    self->close();
            });
    }

    // ---------- ШАГ 2: Читаем запрос от браузера ----------

    void read_client_request() {
        auto self = shared_from_this();
        parser_.emplace();
        reset_deadline();

        http::async_read(
            *client_ssl_stream_, client_buffer_, *parser_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    self->current_req_ = self->parser_->release();
                    self->process_request();
                } else {
                    self->close();
                }
            });
    }

    // ---------- ШАГ 3: Кэш и маршрутизация ----------

    void process_request() {
        cache_key_ = target_domain_ + std::string(current_req_.target());

        std::cout << "[MITM] " << current_req_.method_string() << " " << cache_key_ << "\n";

        if (current_req_.method() == http::verb::get && cache_) {
            if (auto hit = cache_->get(cache_key_)) {
                std::cout << "[CACHE HIT] " << cache_key_ << "\n";
                send_cached_response(*hit);
                return;
            }
            std::cout << "[CACHE MISS] " << target_domain_ << "\n";
        }

        if (target_socket_.is_open()) {
            forward_to_target();
        } else {
            resolve_target();
        }
    }

    void send_cached_response(const std::string& raw) {
        auto self    = shared_from_this();
        auto raw_ptr = std::make_shared<std::string>(raw);

        asio::async_write(
            *client_ssl_stream_, asio::buffer(*raw_ptr),
            [self, raw_ptr](boost::system::error_code ec, std::size_t) {
                if (!ec)
                    self->read_client_request();  // keep-alive loop
                else
                    self->close();
            });
    }

    // ---------- ШАГ 4: Подключаемся к целевому серверу ----------

    void resolve_target() {
        auto self = shared_from_this();
        resolver_.async_resolve(
            target_domain_, "443",
            [self](boost::system::error_code ec, tcp::resolver::results_type results) {
                if (!ec) {
                    asio::async_connect(
                        self->target_socket_, results,
                        [self](boost::system::error_code ec, const tcp::endpoint&) {
                            if (!ec)
                                self->do_target_handshake();
                            else
                                self->close();
                        });
                } else {
                    self->close();
                }
            });
    }

    void do_target_handshake() {
        auto self = shared_from_this();
        target_ssl_stream_.emplace(target_socket_, target_ssl_ctx_);
        SSL_set_tlsext_host_name(target_ssl_stream_->native_handle(), target_domain_.c_str());

        target_ssl_stream_->async_handshake(
            ssl::stream_base::client,
            [self](boost::system::error_code ec) {
                if (!ec) {
                    self->forward_to_target();
                } else {
                    std::cerr << "[MITM] Target handshake failed for "
                              << self->target_domain_ << ": " << ec.message() << "\n";
                    self->close();
                }
            });
    }

    // ---------- ШАГ 5: Запрос → целевой сервер ----------

    void forward_to_target() {
        auto self = shared_from_this();
        current_req_.set(http::field::host, target_domain_);

        http::async_write(
            *target_ssl_stream_, current_req_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec)
                    self->read_target_response();
                else
                    self->close();
            });
    }

    void read_target_response() {
        auto self = shared_from_this();
        current_res_.clear();

        http::async_read(
            *target_ssl_stream_, target_buffer_, current_res_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    if (self->current_req_.method() == http::verb::get && self->cache_) {
                        std::ostringstream oss;
                        oss << self->current_res_;
                        self->cache_->put(self->cache_key_, oss.str());
                    }
                    self->forward_to_client();
                } else {
                    std::cerr << "[MITM] Read from target failed for "
                              << self->target_domain_ << ": " << ec.message() << "\n";
                    self->close();
                }
            });
    }

    // ---------- ШАГ 6: Ответ → браузер ----------

    void forward_to_client() {
        auto self    = shared_from_this();
        auto res_ptr = std::make_shared<http::response<http::string_body>>(std::move(current_res_));

        http::async_write(
            *client_ssl_stream_, *res_ptr,
            [self, res_ptr](boost::system::error_code ec, std::size_t) {
                if (ec) {
                    self->close();
                    return;
                }
                if (res_ptr->keep_alive()) {
                    self->read_client_request();
                } else {
                    self->close();
                }
            });
    }

    // ---------- Закрытие ----------

    void close() {
        boost::system::error_code ec;
        deadline_.cancel();
        if (client_socket_.is_open()) {
            client_socket_.shutdown(tcp::socket::shutdown_both, ec);
            client_socket_.close(ec);
        }
        if (target_socket_.is_open()) {
            target_socket_.shutdown(tcp::socket::shutdown_both, ec);
            target_socket_.close(ec);
        }
    }
};