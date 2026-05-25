#pragma once

#include <array>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <iostream>
#include <memory>
#include <string>

#include "log_server.hpp"
#include "lru_cache.hpp"

namespace asio = boost::asio;
using tcp      = asio::ip::tcp;

// ─────────────────────────────────────────────────────────────────────────────
//  TunnelSession — слепой туннель (без расшифровки TLS).
//
//  Используется для доменов из списка [tunnel] в proxy.conf: OCSP/CRL,
//  pinned-certs (банкинг, мессенджеры), Apple-сервисы и т.п. — везде, где
//  MITM ломает соединение.
//
//  Алгоритм: после CONNECT поднимаем TCP-соединение к таргету и тупо
//  перекидываем байты в обе стороны (client→target и target→client) до
//  закрытия любой из сторон или срабатывания таймаута бездействия.
//
//  Параметр cache в конструкторе игнорируется — туннель ничего не кэширует.
//  Сигнатура сохранена, чтобы ConnectionHandler::send_connect_ok_then мог
//  использовать единый шаблон для MITM- и TUNNEL-сессий.
// ─────────────────────────────────────────────────────────────────────────────
class TunnelSession : public std::enable_shared_from_this<TunnelSession> {
    tcp::socket   client_socket_;
    tcp::socket   target_socket_;
    tcp::resolver resolver_;
    std::string   target_domain_;

    std::array<char, 8192> client_buf_;   // буфер для chunks client→target
    std::array<char, 8192> target_buf_;   // буфер для chunks target→client

    boost::asio::steady_timer deadline_;
    std::atomic<bool>         closed_{false};   // защита от двойного close()

   public:
    TunnelSession(tcp::socket socket, std::string domain,
                  std::shared_ptr<LRUCache> /*cache, не используется*/ = nullptr)
        : client_socket_(std::move(socket)),
          target_socket_(client_socket_.get_executor()),
          resolver_(client_socket_.get_executor()),
          target_domain_(std::move(domain)),
          deadline_(client_socket_.get_executor(), std::chrono::seconds(30)) {}

    void start() {
        reset_deadline();
        resolve_target();
    }

   private:
    // ── Таймаут бездействия ──────────────────────────────────────────────────
    // Каждый успешный read обновляет дедлайн. Если 30 секунд ничего не
    // приходит — обрываем соединение и логируем как TIMEOUT.
    void reset_deadline() {
        deadline_.expires_after(std::chrono::seconds(30));
        auto self = shared_from_this();
        deadline_.async_wait([self](boost::system::error_code ec) {
            if (ec == boost::asio::error::operation_aborted) return;  // штатно отменён
            if (!ec) {
                LogServer::instance().log_timeout(self->target_domain_);
                self->close();
            }
        });
    }

    // ── DNS-резолв и подключение к таргету ───────────────────────────────────
    void resolve_target() {
        auto self = shared_from_this();
        resolver_.async_resolve(
            target_domain_, "443",
            [self](boost::system::error_code ec, tcp::resolver::results_type results) {
                if (!ec) {
                    asio::async_connect(
                        self->target_socket_, results,
                        [self](boost::system::error_code ec, const tcp::endpoint&) {
                            if (!ec) {
                                LogEntry e;
                                e.type   = "TUNNEL";
                                e.method = "CONNECT";
                                e.domain = self->target_domain_;
                                e.info   = "blind tunnel";
                                LogServer::instance().log(std::move(e));
                                self->start_pipe();
                            } else {
                                LogServer::instance().log_error(self->target_domain_,
                                    "Tunnel connect: " + ec.message());
                                self->close();
                            }
                        });
                } else {
                    LogServer::instance().log_error(self->target_domain_,
                        "Tunnel DNS: " + ec.message());
                    self->close();
                }
            });
    }

    // ── Старт двунаправленной перекачки байтов ───────────────────────────────
    void start_pipe() {
        pipe_client_to_target();
        pipe_target_to_client();
    }

    // Направление client → target.
    void pipe_client_to_target() {
        auto self = shared_from_this();
        client_socket_.async_read_some(
            asio::buffer(client_buf_),
            [self](boost::system::error_code ec, std::size_t n) {
                if (!ec) {
                    self->reset_deadline();
                    asio::async_write(
                        self->target_socket_, asio::buffer(self->client_buf_, n),
                        [self](boost::system::error_code ec, std::size_t) {
                            if (!ec) self->pipe_client_to_target();
                            else     self->close();
                        });
                } else {
                    self->close();
                }
            });
    }

    // Направление target → client.
    void pipe_target_to_client() {
        auto self = shared_from_this();
        target_socket_.async_read_some(
            asio::buffer(target_buf_),
            [self](boost::system::error_code ec, std::size_t n) {
                if (!ec) {
                    self->reset_deadline();
                    asio::async_write(
                        self->client_socket_, asio::buffer(self->target_buf_, n),
                        [self](boost::system::error_code ec, std::size_t) {
                            if (!ec) self->pipe_target_to_client();
                            else     self->close();
                        });
                } else {
                    self->close();
                }
            });
    }

    // ── Закрытие сессии ──────────────────────────────────────────────────────
    // Может быть вызван конкурентно с обеих pipe-цепочек И из таймера.
    // closed_.exchange(true) гарантирует, что shutdown/close выполнятся
    // ровно один раз.
    void close() {
        if (closed_.exchange(true)) return;
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
