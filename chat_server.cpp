#include <boost/asio.hpp>
#include <boost/beast/http.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include "lru_cache.h"

namespace asio = boost::asio;
namespace http = boost::beast::http;
using tcp = asio::ip::tcp;



// ==========================================
// 2. Логика сессии (с поддержкой кэширования)
// ==========================================
class ProxySession : public std::enable_shared_from_this<ProxySession> {
    tcp::socket client_socket_;
    tcp::socket target_socket_;
    std::shared_ptr<LRUCache> cache_; // Указатель на глобальный кэш
    
    boost::beast::flat_static_buffer<8192> buffer_;
    http::request_parser<http::empty_body> parser_;
    
    // Переменные для чтения ответа при Cache Miss
    std::string cache_key_;
    boost::beast::multi_buffer target_buffer_;
    http::response<http::string_body> target_res_;

    std::array<char, 8192> client_to_target_buf_;
    std::array<char, 8192> target_to_client_buf_;

public:
    ProxySession(tcp::socket socket, std::shared_ptr<LRUCache> cache) 
        : client_socket_(std::move(socket)), 
          target_socket_(client_socket_.get_executor()),
          cache_(std::move(cache)) {}

    void start() {
        read_http_header();
    }

private:
    void read_http_header() {
        auto self = shared_from_this();
        http::async_read_header(client_socket_, buffer_, parser_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec) self->on_header_read();
                else self->close();
            });
    }

    void on_header_read() {
        auto req = parser_.get();
        std::string host_header = req[http::field::host];
        
        std::string host = host_header;
        std::string port = (req.method() == http::verb::connect) ? "443" : "80";

        if (size_t pos = host_header.find(':'); pos != std::string::npos) {
            host = host_header.substr(0, pos);
            port = host_header.substr(pos + 1);
        }

        // --- ЛОГИКА КЭШИРОВАНИЯ ДЛЯ GET-ЗАПРОСОВ ---
        if (req.method() == http::verb::get) {
            // Формируем уникальный ключ кэша (Host + URI)
            cache_key_ = host + std::string(req.target());
            
            auto cached_response = cache_->get(cache_key_);
            if (cached_response) {
                std::cout << "[CACHE HIT] " << cache_key_ << "\n";
                send_cached_response(*cached_response);
                return; // Завершаем обработку, так как данные взяты из кэша
            }
            std::cout << "[CACHE MISS] " << cache_key_ << " -> Fetching...\n";
        } else {
            std::cout << "[TUNNEL] Connect to: " << host << ":" << port << "\n";
        }
        // ------------------------------------------

        auto resolver = std::make_shared<tcp::resolver>(client_socket_.get_executor());
        auto self = shared_from_this();
        resolver->async_resolve(host, port,
            [self, resolver, req](boost::system::error_code ec, tcp::resolver::results_type results) {
                if (!ec) self->connect_to_target(results, req);
                else self->close();
            });
    }

    // Отправка готовых данных (из кэша или только что прочитанных) клиенту
    void send_cached_response(const std::string& data) {
        auto self = shared_from_this();
        auto res_data = std::make_shared<std::string>(data);
        asio::async_write(client_socket_, asio::buffer(*res_data),
            [self, res_data](boost::system::error_code ec, std::size_t) {
                self->close(); // Закрываем соединение после отправки ответа
            });
    }

    void connect_to_target(tcp::resolver::results_type endpoints, http::request<http::empty_body> req) {
        auto self = shared_from_this();
        asio::async_connect(target_socket_, endpoints,
            [self, req](boost::system::error_code ec, const tcp::endpoint&) {
                if (!ec) {
                    if (req.method() == http::verb::connect) {
                        self->send_connect_ok();
                    } else if (req.method() == http::verb::get) {
                        // Для GET запроса запускаем цикл чтения-кэширования
                        self->forward_and_cache_get_request(req);
                    } else {
                        // Для POST и других пересылаем слепо
                        self->forward_http_request(req);
                    }
                } else {
                    self->close();
                }
            });
    }

    // --- ФАЗА 1: Пересылка запроса серверу ---
    void forward_and_cache_get_request(http::request<http::empty_body> req) {
        auto self = shared_from_this();
        auto req_ptr = std::make_shared<http::request<http::empty_body>>(std::move(req));
        http::async_write(target_socket_, *req_ptr,
            [self, req_ptr](boost::system::error_code ec, std::size_t) {
                if (!ec) self->read_response_from_target();
                else self->close();
            });
    }

    // --- ФАЗА 2: Чтение ответа сервера, сохранение и отправка клиенту ---
    void read_response_from_target() {
        auto self = shared_from_this();
        http::async_read(target_socket_, target_buffer_, target_res_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    // Сериализуем HTTP-ответ в строку
                    std::stringstream ss;
                    ss << self->target_res_;
                    std::string res_str = ss.str();
                    
                    // Кладем в LRU кэш
                    self->cache_->put(self->cache_key_, res_str);
                    
                    // Отправляем клиенту
                    self->send_cached_response(res_str);
                } else {
                    self->close();
                }
            });
    }

    // --- Старые методы туннелирования для HTTPS (CONNECT) ---
    void send_connect_ok() {
        auto self = shared_from_this();
        auto response = std::make_shared<std::string>("HTTP/1.1 200 Connection Established\r\n\r\n");
        asio::async_write(client_socket_, asio::buffer(*response),
            [self, response](boost::system::error_code ec, std::size_t) {
                if (!ec) self->start_bridge();
                else self->close();
            });
    }

    void forward_http_request(http::request<http::empty_body> req) {
        auto self = shared_from_this();
        auto req_ptr = std::make_shared<http::request<http::empty_body>>(std::move(req));
        http::async_write(target_socket_, *req_ptr,
            [self, req_ptr](boost::system::error_code ec, std::size_t) {
                if (!ec) self->start_bridge();
                else self->close();
            });
    }

    void start_bridge() {
        do_read_client();
        do_read_target();
    }

    void do_read_client() {
        auto self = shared_from_this();
        client_socket_.async_read_some(asio::buffer(client_to_target_buf_),
            [self](boost::system::error_code ec, std::size_t n) {
                if (!ec) {
                    asio::async_write(self->target_socket_, asio::buffer(self->client_to_target_buf_, n),
                        [self](boost::system::error_code ec, std::size_t) {
                            if (!ec) self->do_read_client();
                            else self->close();
                        });
                } else { self->close(); }
            });
    }

    void do_read_target() {
        auto self = shared_from_this();
        target_socket_.async_read_some(asio::buffer(target_to_client_buf_),
            [self](boost::system::error_code ec, std::size_t n) {
                if (!ec) {
                    asio::async_write(self->client_socket_, asio::buffer(self->target_to_client_buf_, n),
                        [self](boost::system::error_code ec, std::size_t) {
                            if (!ec) self->do_read_target();
                            else self->close();
                        });
                } else { self->close(); }
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

// ==========================================
// 3. Сервер
// ==========================================
class ProxyServer : public std::enable_shared_from_this<ProxyServer>{
    tcp::acceptor acceptor_;
    std::shared_ptr<LRUCache> cache_;

public:
    ProxyServer(asio::io_context& ctx, unsigned short port, std::shared_ptr<LRUCache> cache)
        : acceptor_(ctx, {tcp::v4(), port}), cache_(std::move(cache)) { }

    void do_accept() {
        auto session_strand = asio::make_strand(acceptor_.get_executor());
        acceptor_.async_accept(session_strand,
            [self = shared_from_this()](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<ProxySession>(std::move(socket), self->cache_)->start();
                }
                self->do_accept();
            });
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: server <threads>\n" ;
        return EXIT_FAILURE;
    }
    auto const threads = std::max<int>(1, std::atoi(argv[1]));

    asio::io_context ioc{threads};

    // Создаем глобальный кэш на 1000 записей
    auto shared_cache = std::make_shared<LRUCache>(1000);

    // Передаем кэш в сервер
    std::make_shared<ProxyServer>(ioc, 8080, shared_cache)->do_accept();

    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for(auto i = threads - 1; i > 0; --i)
        v.emplace_back(
        [&ioc, i] {
            std::cout << "thread " << i << " is running\n";
            ioc.run();
        });

    ioc.run();

    // Ждем завершения потоков (исправление потенциального краша)
    for (auto& t : v) {
        if (t.joinable()) {
            t.join(); 
        }
    }

    return 0;
}