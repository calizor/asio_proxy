#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>

#include <atomic>
#include <chrono>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>

#include "cert_manager.hpp"
#include "log_server.hpp"
#include "lru_cache.hpp"

namespace asio = boost::asio;
namespace ssl  = boost::asio::ssl;
namespace http = boost::beast::http;
using tcp      = asio::ip::tcp;

// ─────────────────────────────────────────────────────────────────────────────
//  MitmSession — расшифровка TLS и проксирование HTTP-запросов с кэшем.
//
//  Жизненный цикл одного соединения:
//   1. do_client_handshake()   — TLS-handshake с клиентом, на лету выдаём
//                                сертификат для target_domain_ через CertManager.
//   2. read_client_request()   — читаем HTTP-запрос от клиента.
//   3. process_request()       — проверяем кэш; на HIT отдаём из кэша и
//                                возвращаемся к шагу 2 (keep-alive).
//   4. resolve_target()        — DNS-резолв таргета.
//   5. connect_target()        — TCP-коннект + TLS-handshake к серверу.
//   6. forward_to_target()     — пересылаем запрос серверу.
//   7. read_target_response()  — читаем ответ, кладём в кэш (если можно).
//   8. forward_to_client()     — отдаём ответ клиенту.
//   9. Если keep-alive — возвращаемся к шагу 2.
//
//  Кэширование:
//   - Ключ = target_domain_ + path (без учёта Vary и query-busters).
//   - Решение о хранении: response_is_storable + is_cacheable_status.
//   - TTL: max-age / Expires / эвристика по Last-Modified / дефолт 300с.
//   - Bypass (no-cache/max-age=0 в запросе) НЕ удаляет запись, только
//     обходит её для текущего запроса.
// ─────────────────────────────────────────────────────────────────────────────
class MitmSession : public std::enable_shared_from_this<MitmSession> {
    tcp::socket   client_socket_;
    tcp::socket   target_socket_;
    tcp::resolver resolver_;

    // TLS-стрим с клиентом: ssl::stream поверх ссылки на client_socket_.
    std::optional<ssl::stream<tcp::socket&>> client_ssl_stream_;

    // TLS-стрим к таргету: контекст один на сессию, проверяем цепочку
    // системными корнями.
    ssl::context                             target_ssl_ctx_{ssl::context::tls_client};
    std::optional<ssl::stream<tcp::socket&>> target_ssl_stream_;

    boost::beast::flat_buffer                              client_buffer_;
    boost::beast::flat_buffer                              target_buffer_;
    std::optional<http::request_parser<http::string_body>> parser_;

    http::request<http::string_body>  current_req_;
    http::response<http::string_body> current_res_;

    std::shared_ptr<LRUCache> cache_;
    std::string               cache_key_;
    std::string               target_domain_;

    boost::asio::steady_timer deadline_;
    std::atomic<bool>         closed_{false};

    // Точка отсчёта для измерения латентности запроса.
    std::chrono::steady_clock::time_point req_start_;

   public:
    MitmSession(tcp::socket socket, std::string domain,
                std::shared_ptr<LRUCache> cache = nullptr)
        : client_socket_(std::move(socket)),
          target_socket_(client_socket_.get_executor()),
          resolver_(client_socket_.get_executor()),
          cache_(std::move(cache)),
          target_domain_(std::move(domain)),
          deadline_(client_socket_.get_executor(), std::chrono::seconds(30)) {
        target_ssl_ctx_.set_default_verify_paths();
        // Проверяем сертификат сервера — это защита от MITM на участке
        // прокси→сервер. С отключённой проверкой кто угодно мог бы
        // подсунуть нам поддельный ответ.
        target_ssl_ctx_.set_verify_mode(ssl::verify_peer);
    }

    void start() {
        reset_deadline();
        do_client_handshake();
    }

   private:
    // ── Таймаут бездействия ──────────────────────────────────────────────────
    // Каждое успешное I/O обновляет дедлайн. По истечении — закрываем
    // соединение и логируем TIMEOUT.
    void reset_deadline(std::chrono::seconds timeout = std::chrono::seconds(30)) {
        deadline_.expires_after(timeout);
        auto self = shared_from_this();
        deadline_.async_wait([self](boost::system::error_code ec) {
            if (ec == boost::asio::error::operation_aborted) return;
            if (!ec) {
                LogServer::instance().log_timeout(self->target_domain_);
                self->close();
            }
        });
    }

    // ── TLS-handshake с клиентом ─────────────────────────────────────────────
    // Берём (или генерируем) ssl::context для target_domain_ и поднимаем
    // TLS-сессию в роли сервера. Клиент проверяет наш сертификат против
    // установленного rootCA — поэтому rootCA.crt должен быть в его truststore.
    void do_client_handshake() {
        auto self        = shared_from_this();
        auto session_ctx = CertManager::get_context_for_domain(target_domain_);

        if (!session_ctx) {
            LogServer::instance().log_error(target_domain_, "No SSL context");
            close();
            return;
        }

        client_ssl_stream_.emplace(client_socket_, *session_ctx);
        client_ssl_stream_->async_handshake(
            ssl::stream_base::server,
            [self](boost::system::error_code ec) {
                if (!ec)
                    self->read_client_request();
                else {
                    LogServer::instance().log_error(self->target_domain_,
                        "Client TLS handshake: " + ec.message());
                    self->close();
                }
            });
    }

    // ── Чтение HTTP-запроса от клиента ───────────────────────────────────────
    // Создаём свежий парсер на каждый запрос (под keep-alive). После успеха
    // переходим в process_request, где решается кэш-логика.
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

    // ── Обработка запроса: проверка кэша + решение о форварде ────────────────
    void process_request() {
        cache_key_ = target_domain_ + std::string(current_req_.target());
        req_start_ = std::chrono::steady_clock::now();

        const std::string method = std::string(current_req_.method_string());
        const std::string path   = std::string(current_req_.target());

        LogServer::instance().log_mitm(method, target_domain_, path);

        if (current_req_.method() == http::verb::get && cache_) {
            const std::string cc_req     = std::string(current_req_[http::field::cache_control]);
            const std::string pragma_req = std::string(current_req_[http::field::pragma]);

            if (cache_control::request_bypasses_cache(cc_req, pragma_req)) {
                // Клиент требует свежий ответ — обходим кэш ТОЛЬКО для этого
                // запроса. По RFC 7234 §5.2.1.4 директива no-cache в запросе
                // означает «ревалидируй прежде чем использовать», а не
                // «удали из хранилища». Удаление здесь делало бы кэш-прокси
                // бесполезным при hard-reload и при обычном reload (max-age=0).
                LogEntry bypass_entry;
                bypass_entry.type   = "CACHE_BYPASS";
                bypass_entry.method = "GET";
                bypass_entry.domain = target_domain_;
                bypass_entry.path   = path;
                bypass_entry.info   = "cache bypassed by request directive";
                LogServer::instance().log(std::move(bypass_entry));
            } else if (auto hit = cache_->get(cache_key_)) {
                LogServer::instance().log_cache_hit(target_domain_, path);
                send_cached_response(*hit);
                return;
            } else {
                LogServer::instance().log_cache_miss(target_domain_);
            }
        }

        // В рамках keep-alive target_socket_ может уже быть подключён к
        // нужному хосту — переиспользуем соединение, экономим TLS-handshake.
        if (target_socket_.is_open()) {
            forward_to_target();
        } else {
            resolve_target();
        }
    }

    // ── Отдача готового ответа из кэша ───────────────────────────────────────
    // Пишем сериализованный response (заголовки + тело) в клиентский TLS-стрим.
    // После успешной записи возвращаемся к чтению следующего запроса —
    // это нужно для корректной работы keep-alive.
    void send_cached_response(const std::string& raw) {
        auto self    = shared_from_this();
        auto raw_ptr = std::make_shared<std::string>(raw);

        asio::async_write(
            *client_ssl_stream_, asio::buffer(*raw_ptr),
            [self, raw_ptr](boost::system::error_code ec, std::size_t) {
                if (!ec)
                    self->read_client_request();
                else
                    self->close();
            });
    }

    // ── DNS-резолв таргета и TCP-коннект ─────────────────────────────────────
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
                            else {
                                LogServer::instance().log_error(self->target_domain_,
                                    "Connect failed: " + ec.message());
                                self->close();
                            }
                        });
                } else {
                    LogServer::instance().log_error(self->target_domain_,
                        "DNS failed: " + ec.message());
                    self->close();
                }
            });
    }

    // ── TLS-handshake с таргетом ─────────────────────────────────────────────
    // SNI (через SSL_set_tlsext_host_name) обязателен — без него многие
    // сервера на shared IP не понимают, какой сертификат отдавать.
    // host_name_verification дополнительно сверяет CN/SAN с именем хоста.
    void do_target_handshake() {
        auto self = shared_from_this();
        target_ssl_stream_.emplace(target_socket_, target_ssl_ctx_);
        SSL_set_tlsext_host_name(target_ssl_stream_->native_handle(), target_domain_.c_str());
        target_ssl_stream_->set_verify_callback(ssl::host_name_verification(target_domain_));

        target_ssl_stream_->async_handshake(
            ssl::stream_base::client,
            [self](boost::system::error_code ec) {
                if (!ec) {
                    self->forward_to_target();
                } else {
                    LogServer::instance().log_error(self->target_domain_,
                        "Target TLS: " + ec.message());
                    self->close();
                }
            });
    }

    // ── Пересылка запроса серверу ────────────────────────────────────────────
    // Принудительно ставим заголовок Host в чистый домен (без порта) — для
    // совместимости с серверами, которые матчат vhost по точному значению.
    void forward_to_target() {
        auto self = shared_from_this();
        current_req_.set(http::field::host, target_domain_);
        reset_deadline();

        http::async_write(
            *target_ssl_stream_, current_req_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec)
                    self->read_target_response();
                else {
                    LogServer::instance().log_error(self->target_domain_,
                        "Forward write: " + ec.message());
                    self->close();
                }
            });
    }

    // ── Чтение ответа от сервера + решение о кэшировании ─────────────────────
    void read_target_response() {
        auto self = shared_from_this();
        current_res_.clear();
        // Сбрасываем остатки прошлого ответа из буфера — иначе на keep-alive
        // парсер увидит хвост предыдущего тела и пойдёт по неправильной ветке.
        target_buffer_.consume(target_buffer_.size());
        reset_deadline();

        http::async_read(
            *target_ssl_stream_, target_buffer_, current_res_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    auto   elapsed = std::chrono::steady_clock::now() - self->req_start_;
                    double ms      = std::chrono::duration<double, std::milli>(elapsed).count();

                    int         status = static_cast<int>(self->current_res_.result_int());
                    std::size_t bytes  = self->current_res_.body().size();
                    std::string path   = std::string(self->current_req_.target());
                    std::string ct     = std::string(self->current_res_[http::field::content_type]);

                    // ── Кэширование ответа ─────────────────────────────────
                    // По RFC 7231 §6.1 / RFC 7234 §4.2.2 эвристически кэшируемые
                    // статусы: 200, 203, 204, 206, 300, 301, 308, 404, 405, 410,
                    // 414, 501. Статусы 302/307 кэшируются только при наличии
                    // явных max-age/Expires (это динамические редиректы).
                    if (self->current_req_.method() == http::verb::get && self->cache_) {
                        const std::string cc_res     = std::string(self->current_res_[http::field::cache_control]);
                        const std::string pragma_res = std::string(self->current_res_[http::field::pragma]);
                        const std::string expires_h  = std::string(self->current_res_[http::field::expires]);

                        if (is_cacheable_status(status, cc_res, expires_h)) {
                            // Vary: * означает «всегда разные» — не кэшируем.
                            // Конкретные значения Vary (Accept-Encoding и пр.)
                            // не поддерживаются — это требует ключа кэша,
                            // учитывающего значения соответствующих заголовков.
                            const std::string vary    = std::string(self->current_res_[http::field::vary]);
                            const bool vary_blocks    = (vary.find('*') != std::string::npos);

                            if (!vary_blocks && cache_control::response_is_storable(cc_res, pragma_res)) {
                                const std::string date_h    = std::string(self->current_res_[http::field::date]);
                                const std::string lastmod_h = std::string(self->current_res_[http::field::last_modified]);

                                long ttl_s = cache_control::compute_ttl_seconds(
                                    cc_res, expires_h, date_h, lastmod_h);

                                if (ttl_s > 0) {
                                    // ВНИМАНИЕ: для ответов с Transfer-Encoding:
                                    // chunked сериализация через oss << res
                                    // оставит заголовок chunked, хотя тело уже
                                    // распаковано. Это потенциальный источник
                                    // багов при отдаче из кэша — TODO:
                                    // вызвать current_res_.prepare_payload()
                                    // перед сериализацией.
                                    std::ostringstream oss;
                                    oss << self->current_res_;
                                    self->cache_->put(self->cache_key_, oss.str(),
                                                      std::chrono::seconds{ttl_s});
                                }
                            }
                        }
                    }

                    // ── Логирование тела (для веб-панели) ──────────────────
                    // Сохраняем тело только для текстовых типов и только
                    // несжатое (gzip/br не распаковываем). Лимит — BODY_MAX_BYTES.
                    std::string body;
                    bool        truncated = false;
                    const std::string encoding =
                        std::string(self->current_res_[http::field::content_encoding]);
                    const bool is_compressed = !encoding.empty();

                    if (is_text_content_type(ct) && !is_compressed) {
                        const std::string& raw = self->current_res_.body();
                        if (raw.size() > BODY_MAX_BYTES) {
                            body      = raw.substr(0, BODY_MAX_BYTES);
                            truncated = true;
                        } else {
                            body = raw;
                        }
                    }

                    LogServer::instance().log_response(
                        self->target_domain_, path, status, bytes, ms, ct, body, truncated);

                    // ── Закрытие target-соединения, если сервер не keep-alive ─
                    // Сбрасываем TLS-стрим и сокет, чтобы следующий запрос в
                    // этой же сессии прошёл через переподключение.
                    if (!self->current_res_.keep_alive()) {
                        boost::system::error_code tec;
                        if (self->target_ssl_stream_)
                            self->target_ssl_stream_->shutdown(tec);
                        self->target_socket_.close(tec);
                        self->target_ssl_stream_.reset();
                        self->target_buffer_.clear();
                    }

                    self->forward_to_client();
                } else {
                    LogServer::instance().log_error(self->target_domain_,
                        "Read response: " + ec.message());
                    self->close();
                }
            });
    }

    // ── Пересылка ответа клиенту ─────────────────────────────────────────────
    // После отправки ответа возвращаемся к чтению нового запроса (keep-alive).
    // Таймаут уменьшен до 15 секунд — между запросами в одной сессии нет
    // смысла держать соединение дольше.
    void forward_to_client() {
        auto self    = shared_from_this();
        auto res_ptr = std::make_shared<http::response<http::string_body>>(
                            std::move(current_res_));

        http::async_write(
            *client_ssl_stream_, *res_ptr,
            [self, res_ptr](boost::system::error_code ec, std::size_t) {
                if (ec) { self->close(); return; }
                self->reset_deadline(std::chrono::seconds(15));
                self->read_client_request();
            });
    }

    // ── Закрытие сессии ──────────────────────────────────────────────────────
    // Может быть вызван конкурентно (таймер + сбой async-операции).
    // closed_.exchange(true) гарантирует выполнение ровно один раз.
    void close() {
        if (closed_.exchange(true)) return;
        boost::system::error_code ec;
        deadline_.cancel();
        // Сбрасываем TLS-стримы ДО закрытия нижележащих сокетов.
        // ssl::stream держит ссылку на сокет; разрушив его первым, мы
        // гарантируем, что ни один async-handler не выстрелит по уже
        // закрытому сокету.
        client_ssl_stream_.reset();
        target_ssl_stream_.reset();
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