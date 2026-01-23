#include <boost/asio.hpp>
#include <boost/beast/http.hpp>
#include <iostream>
#include <memory>
#include <string>

namespace asio = boost::asio;
namespace http = boost::beast::http;
using tcp = asio::ip::tcp;

// Класс сессии, который управляет жизнью одного подключения
class ProxySession : public std::enable_shared_from_this<ProxySession> {
    tcp::socket client_socket_;
    tcp::socket target_socket_;
    boost::beast::flat_static_buffer<8192> buffer_;
    http::request_parser<http::empty_body> parser_;
    http::request<http::string_body> req_;
    
    // Буферы для перекачки данных (bridge)
    std::array<char, 8192> client_to_target_buf_;
    std::array<char, 8192> target_to_client_buf_;

public:
    ProxySession(tcp::socket socket) 
        : client_socket_(std::move(socket)), 
          target_socket_(client_socket_.get_executor()) {}

    void start() {
        read_http_header();
    }

private:
    void read_http_header() {
        auto self = shared_from_this();
        http::async_read_header(client_socket_, buffer_, parser_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec) self->on_header_read();
            });
    }

    void on_header_read() {
        auto req = parser_.get();
        std::string host_header = req[http::field::host];
        
        // Базовый парсинг хоста и порта
        std::string host = host_header;
        std::string port = (req.method() == http::verb::connect) ? "443" : "80";

        if (size_t pos = host_header.find(':'); pos != std::string::npos) {
            host = host_header.substr(0, pos);
            port = host_header.substr(pos + 1);
        }

        std::cout << "Connect to: " << host << ":" << port << std::endl;

        // Резолвим адрес
        auto resolver = std::make_shared<tcp::resolver>(client_socket_.get_executor());
        auto self = shared_from_this();
        resolver->async_resolve(host, port,
            [self, resolver, req](boost::system::error_code ec, tcp::resolver::results_type results) {
                if (!ec) self->connect_to_target(results, req);
            });
    }

    void connect_to_target(tcp::resolver::results_type endpoints, http::request<http::empty_body> req) {
        auto self = shared_from_this();
        asio::async_connect(target_socket_, endpoints,
            [self, req](boost::system::error_code ec, const tcp::endpoint&) {
                if (ec) return;

                if (req.method() == http::verb::connect) {
                    self->send_connect_ok();
                } else {
                    self->forward_http_request(req);
                }
            });
    }

    void send_connect_ok() {
        auto self = shared_from_this();
        auto response = std::make_shared<std::string>("HTTP/1.1 200 Connection Established\r\n\r\n");
        asio::async_write(client_socket_, asio::buffer(*response),
            [self, response](boost::system::error_code ec, std::size_t) {
                if (!ec) self->start_bridge();
            });
    }

    void forward_http_request(http::request<http::empty_body> req) {
        auto self = shared_from_this();
        // Используем shared_ptr для req, чтобы он жил до конца отправки
        auto req_ptr = std::make_shared<http::request<http::empty_body>>(std::move(req));
        http::async_write(target_socket_, *req_ptr,
            [self, req_ptr](boost::system::error_code ec, std::size_t) {
                if (!ec) self->start_bridge();
            });
    }

    // Запускаем двустороннюю перекачку
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
                        });
                } else { self->close(); }
            });
    }

    void close() {
        if (client_socket_.is_open()) client_socket_.close();
        if (target_socket_.is_open()) target_socket_.close();
    }
};

// Сервер, принимающий новые подключения
class ProxyServer {
    tcp::acceptor acceptor_;

public:
    ProxyServer(asio::io_context& ctx, short port)
        : acceptor_(ctx, {tcp::v4(), port}) {
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<ProxySession>(std::move(socket))->start();
                }
                do_accept();
            });
    }
};

int main() {
    try {
        asio::io_context ctx;
        ProxyServer server(ctx, 8080);
        std::cout << "Proxy running on port 8080..." << std::endl;
        ctx.run();
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}