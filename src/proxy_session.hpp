#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio/steady_timer.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <optional>
#include <sstream>


#include "cert_manager.hpp"
#include "lru_cache.hpp" 

namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
namespace http = boost::beast::http;
using tcp = asio::ip::tcp;

// Заглушка, если LRUCache еще не вынесен в отдельный файл

class ProxySession : public std::enable_shared_from_this<ProxySession> {
    tcp::socket client_socket_;
    tcp::socket target_socket_;
    tcp::resolver resolver_;

    // --- SSL для связи с Браузером (Мы - сервер) ---
    std::optional<ssl::stream<tcp::socket&>> client_ssl_stream_;
    
    // --- SSL для связи с Целевым сервером (Мы - клиент) ---
    ssl::context target_ssl_ctx_{ssl::context::tls_client};
    std::optional<ssl::stream<tcp::socket&>> target_ssl_stream_;

    // Буфер и парсеры
    boost::beast::flat_buffer buffer_;
    std::optional<http::request_parser<http::string_body>> parser_;
    
    // Хранилище для запроса и ответа
    http::request<http::string_body> current_req_;
    http::response<http::string_body> current_res_;

    std::shared_ptr<LRUCache> cache_; // Указатель на глобальный кэш
    std::string cache_key_;
    std::string target_domain_;

    boost::asio::steady_timer deadline_;

public:
    ProxySession(tcp::socket socket, std::shared_ptr<LRUCache> cache = nullptr) 
        : client_socket_(std::move(socket)), 
          target_socket_(client_socket_.get_executor()),
          resolver_(client_socket_.get_executor()),
          cache_(cache),
          deadline_(socket.get_executor(),std::chrono::seconds(30)) {
        
        // Настраиваем SSL-клиента (чтобы прокси доверял серверам в интернете)
        target_ssl_ctx_.set_default_verify_paths();
    }

    void start() {
        start_timer();
        parser_.emplace();
        read_http_header();
    }


    void start_timer() {
        auto self = shared_from_this();
        // Ждем истечения таймера
        deadline_.async_wait([self](boost::system::error_code ec) {
            // 1. Проверяем, не отменили ли таймер ручным сбросом
            if (ec == boost::asio::error::operation_aborted) {
                return; // Всё отлично, таймер просто перезапустили, ничего не закрываем!
            }
            // 2. Если другой ошибки нет, значит время реально вышло
            if (!ec) {
                std::cout << "[TIMEOUT] Время вышло, закрываем сокет. "<< self->target_domain_ << "\n";
                self->close();
            }
        });
}

private:
    void read_http_header() {
        auto self = shared_from_this();
        http::async_read_header(client_socket_, buffer_, *parser_, //у optional перегружен оператор *; same as parser_.value();
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec) self->on_header_read();
                else self->close();
            });
    }

    void on_header_read() {
        auto req = parser_->get();
        std::string host_header = req[http::field::host];
        
        if (req.method() == http::verb::connect) {
            target_domain_ = host_header;
            if (size_t pos = target_domain_.find(':'); pos != std::string::npos) { // if statement with initializer, pos lives in if and else block
                target_domain_ = target_domain_.substr(0, pos);
            }
            std::cout << "\n[MITM] Intercepted CONNECT to: " << target_domain_ << "\n";
            send_connect_ok();
        } else {
            // Здесь можно добавить обработку обычного HTTP, но пока закроем
            close();
        }
    }

    // --- ШАГ 1: Установка MITM-туннеля с браузером ---
   void send_connect_ok() {
        auto self = shared_from_this();
        auto response = std::make_shared<std::string>("HTTP/1.1 200 Connection Established\r\n\r\n");
        
        asio::async_write(client_socket_, asio::buffer(*response),
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    // 1. Берем готовый SSL-контекст из ОЗУ (Или генерируем, если это первый раз)
                    auto session_ctx = CertManager::get_context_for_domain(self->target_domain_);
                    
                    if (!session_ctx) {
                        std::cerr << "[MITM] Failed to get SSL context for " << self->target_domain_ << "\n";
                        self->close(); 
                        return;
                    }

                    // 2. Оборачиваем сокет с использованием этого контекста
                    self->client_ssl_stream_.emplace(self->client_socket_, *session_ctx);
                    
                    // 3. Выполняем Handshake
                    self->client_ssl_stream_->async_handshake(ssl::stream_base::server,
                        [self](boost::system::error_code ec) {
                            if (!ec) self->read_decrypted_request();
                            else self->close();
                        });
                } else self->close();
            });
    }

    // --- ШАГ 2: Читаем расшифрованный запрос от браузера ---
    void read_decrypted_request() {
        auto self = shared_from_this();
        parser_.emplace(); // Сбрасываем парсер для нового чтения
        
        deadline_.expires_after(std::chrono::seconds(30));      //таймер сессии
        start_timer();

        http::async_read(*client_ssl_stream_, buffer_, *parser_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    self->current_req_ = self->parser_->release();
                    self->process_request();
                } else self->close();
            });
    }

    // --- ШАГ 3: Проверка КЭША и маршрутизация ---
    void process_request() {
        // Формируем уникальный ключ для кэша
        cache_key_ = target_domain_ + std::string(current_req_.target());
        
        std::cout << "[PROXY] Processing: " << current_req_.method_string() << " " << cache_key_ << "\n";

        // Если это GET-запрос, проверяем кэш
        if (current_req_.method() == http::verb::get && cache_ != nullptr) {
            auto cached_body = cache_->get(cache_key_); // Предполагаем, что метод get() возвращает std::optional<string>
            if (cached_body) {
                std::cout << "[CACHE HIT] " << cache_key_ << "\n";
                send_cached_response(*cached_body);
                return;
            }
           std::cout << "[CACHE MISS] Fetching from " << target_domain_ << "...\n";
        }

        resolve_target();
    }

    // Отправка данных из кэша (мгновенно)
    void send_cached_response(const std::string& raw_http_response) {
        auto self = shared_from_this();
        
        // Создаем умный указатель на строку, чтобы она жила, пока идет асинхронная отправка
        auto res_ptr = std::make_shared<std::string>(raw_http_response);

        // Пишем сырую строку напрямую в SSL-стрим браузера (Boost Asio сам всё поймет)
        asio::async_write(*client_ssl_stream_, asio::buffer(*res_ptr),
            [self, res_ptr](boost::system::error_code ec, std::size_t) {
                if (ec) {
                    self->close();
                    return;
                }
                if (self->current_req_.keep_alive()) {
                    self->read_decrypted_request(); 
                } else {
                    self->close(); 
                }
        });
    }

    // ---ШАГ 4: Подключение к целевому серверу---
    void resolve_target() {
        auto self = shared_from_this();
        resolver_.async_resolve(target_domain_, "443",
            [self](boost::system::error_code ec, tcp::resolver::results_type results) {
                if (!ec) {
                    asio::async_connect(self->target_socket_, results,
                        [self](boost::system::error_code ec, const tcp::endpoint&) {
                            if (!ec) self->perform_target_handshake();
                            else self->close();
                        });
                } else self->close();
            });
    }

    void perform_target_handshake() {
        auto self = shared_from_this();
        // Оборачиваем сокет в SSL-клиент
        target_ssl_stream_.emplace(target_socket_, target_ssl_ctx_);
        
        // SNI (Указываем серверу, к какому домену мы обращаемся)
        SSL_set_tlsext_host_name(target_ssl_stream_->native_handle(), target_domain_.c_str());

        target_ssl_stream_->async_handshake(ssl::stream_base::client,
            [self](boost::system::error_code ec) {
                if (!ec) self->forward_request_to_target();
                else self->close();
            });
    }

    // --- ШАГ 5: Пересылка запроса и получение ответа ---
    void forward_request_to_target() {
        auto self = shared_from_this();
        // Переписываем заголовок Host на всякий случай
        current_req_.set(http::field::host, target_domain_);
        
        http::async_write(*target_ssl_stream_, current_req_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec) self->read_response_from_target();
                else self->close();
            });
    }

    void read_response_from_target() {
        auto self = shared_from_this();
        // Очищаем буфер перед чтением ответа
        buffer_.consume(buffer_.size()); 
        
        http::async_read(*target_ssl_stream_, buffer_, current_res_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    if (self->current_req_.method() == http::verb::get && self->cache_ != nullptr) {
                        // Сериализуем ВЕСЬ HTTP-ответ (заголовки + тело) в строку
                        std::ostringstream oss;
                        oss << self->current_res_; 
                        
                        // Кладем в кэш готовую сырую HTTP-строку
                        self->cache_->put(self->cache_key_, oss.str());
                    }
                    self->forward_response_to_client();
                } else self->close();
            });
    }

    // --- ШАГ 6: Возвращаем ответ браузеру ---
    void forward_response_to_client() {
        auto self = shared_from_this();
        auto res_ptr = std::make_shared<http::response<http::string_body>>(std::move(current_res_));
        
        http::async_write(*client_ssl_stream_, *res_ptr,
        [self, res_ptr](boost::system::error_code ec, std::size_t) {
            // 1. Если при отправке произошла ошибка (например, юзер закрыл вкладку)
            if (ec) {
                self->close();
                return;
            }

            if (res_ptr->keep_alive()) {
                self->read_decrypted_request(); 
            } else {
                // Закрываем только если браузер или сервер прямо попросили об этом 
                // (например, прислали заголовок Connection: close)
                self->close();
            }
        });
    }

    void close() {
        boost::system::error_code ec;
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