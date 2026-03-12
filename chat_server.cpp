#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp> // <-- ДОБАВИЛИ SSL
#include <boost/beast/http.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <optional>

namespace asio = boost::asio;
namespace ssl = boost::asio::ssl; // <-- Неймспейс SSL
namespace http = boost::beast::http;
using tcp = asio::ip::tcp;

class ProxySession : public std::enable_shared_from_this<ProxySession> {
    tcp::socket client_socket_;
    tcp::socket target_socket_;
    std::shared_ptr<ssl::context> ssl_ctx_; // <-- Храним SSL контекст
    
    // Стрим для перехваченного защищенного соединения
    std::optional<ssl::stream<tcp::socket&>> client_ssl_stream_;

    boost::beast::flat_static_buffer<8192> buffer_;
    
    // Делаем парсер опциональным, чтобы его можно было сбросить 
    // перед чтением расшифрованного запроса
    std::optional<http::request_parser<http::string_body>> parser_;

public:
    ProxySession(tcp::socket socket, std::shared_ptr<ssl::context> ssl_ctx) 
        : client_socket_(std::move(socket)), 
          target_socket_(client_socket_.get_executor()),
          ssl_ctx_(std::move(ssl_ctx)) {}

    void start() {
        parser_.emplace(); // Инициализируем парсер
        read_http_header();
    }

private:
    void read_http_header() {
        auto self = shared_from_this();
        http::async_read_header(client_socket_, buffer_, *parser_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec) self->on_header_read();
                else self->close();
            });
    }

    void on_header_read() {
        auto req = parser_->get();
        std::string host_header = req[http::field::host];
        
        // [MITM] Если это HTTPS запрос (CONNECT)
        if (req.method() == http::verb::connect) {
            std::cout << "\n[MITM] Intercepted CONNECT to: " << host_header << "\n";
            send_connect_ok();
            return;
        }

        // Если это обычный HTTP, просто закрываем (пока нас интересует только HTTPS)
        std::cout << "Ignoring regular HTTP request to: " << host_header << "\n";
        close();
    }

    void send_connect_ok() {
        auto self = shared_from_this();
        auto response = std::make_shared<std::string>("HTTP/1.1 200 Connection Established\r\n\r\n");
        
        // Отправляем браузеру подтверждение в открытом виде
        asio::async_write(client_socket_, asio::buffer(*response),
            [self, response](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    // [MITM] Браузер думает, что туннель готов. Сейчас он начнет слать шифрованные байты.
                    // Оборачиваем наш сырой сокет в SSL-стрим!
                    self->client_ssl_stream_.emplace(self->client_socket_, *self->ssl_ctx_);
                    
                    // Выполняем "рукопожатие" (Handshake), выступая в роли сервера
                    self->client_ssl_stream_->async_handshake(ssl::stream_base::server,
                        [self](boost::system::error_code ec) {
                            if (!ec) {
                                std::cout << "[MITM] SSL Handshake successful! Reading decrypted data...\n";
                                self->read_decrypted_request();
                            } else {
                                std::cerr << "[MITM] Handshake failed: " << ec.message() << "\n";
                                self->close();
                            }
                        });
                } else self->close();
            });
    }

    void read_decrypted_request() {
        auto self = shared_from_this();
        
        // Сбрасываем парсер, чтобы прочитать новый (уже расшифрованный) запрос
        parser_.emplace();
        
        // ВАЖНО: Теперь мы читаем из client_ssl_stream_, а не из client_socket_!
        http::async_read(*client_ssl_stream_, buffer_, *parser_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    auto req = self->parser_->get();
                    std::cout << "[MITM] SUCCESS! Decrypted request: " << req.method_string() << " " << req.target() << "\n";
                    
                    // Отдаем браузеру фейковую страницу через зашифрованный туннель
                    self->send_fake_ssl_response();
                } else {
                    self->close();
                }
            });
    }

    void send_fake_ssl_response() {
        auto self = shared_from_this();
        
        // Формируем обычный HTTP ответ
        auto res = std::make_shared<http::response<http::string_body>>(http::status::ok, 11);
        res->set(http::field::server, "MyMITMProxy");
        res->set(http::field::content_type, "text/html");
        res->body() = "<h1>Hello from MITM Proxy!</h1><p>I decrypted your HTTPS traffic!</p>";
        res->prepare_payload();

        // Пишем в SSL-стрим (OpenSSL сам зашифрует эти данные перед отправкой в сеть)
        http::async_write(*client_ssl_stream_, *res,
            [self, res](boost::system::error_code ec, std::size_t) {
                std::cout << "[MITM] Fake response sent. Closing connection.\n";
                self->close();
            });
    }

    void close() {
        boost::system::error_code ec;
        if (client_socket_.is_open()) {
            client_socket_.shutdown(tcp::socket::shutdown_both, ec);
            client_socket_.close(ec);
        }
    }
};

class ProxyServer : public std::enable_shared_from_this<ProxyServer>{
    tcp::acceptor acceptor_;
    std::shared_ptr<ssl::context> ssl_ctx_;

public:
    ProxyServer(asio::io_context& ctx, unsigned short port, std::shared_ptr<ssl::context> ssl_ctx)
        : acceptor_(ctx, {tcp::v4(), port}), ssl_ctx_(std::move(ssl_ctx)) { }

    void do_accept() {
        auto session_strand = asio::make_strand(acceptor_.get_executor());
        acceptor_.async_accept(session_strand,
            [self = shared_from_this()](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<ProxySession>(std::move(socket), self->ssl_ctx_)->start();
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

    // --- НАСТРОЙКА SSL КОНТЕКСТА ДЛЯ СЕРВЕРА ---
    auto ssl_ctx = std::make_shared<ssl::context>(ssl::context::tls_server);
    ssl_ctx->set_options(
        ssl::context::default_workarounds |
        ssl::context::no_sslv2 |
        ssl::context::no_sslv3 |
        ssl::context::no_tlsv1 |
        ssl::context::no_tlsv1_1
    );
    
    // Подгружаем наши сгенерированные сертификаты
   try {
        ssl_ctx->use_certificate_chain_file("google.crt");
        ssl_ctx->use_private_key_file("google.key", ssl::context::pem);
    } catch (std::exception& e) {
        std::cerr << "CRITICAL ERROR: " << e.what() << "\n";
        return EXIT_FAILURE;
    }

    std::make_shared<ProxyServer>(ioc, 8080, ssl_ctx)->do_accept();

    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for(auto i = threads - 1; i > 0; --i)
        v.emplace_back([&ioc] { ioc.run(); });

    ioc.run();

    for (auto& t : v) {
        if (t.joinable()) t.join(); 
    }

    return 0;
}