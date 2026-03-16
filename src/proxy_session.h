#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/http.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <optional>

#include "cert_manager.h" // Подключаем наш генератор сертификатов

namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
namespace http = boost::beast::http;
using tcp = asio::ip::tcp;

class ProxySession : public std::enable_shared_from_this<ProxySession> {
    tcp::socket client_socket_;
    std::optional<ssl::stream<tcp::socket&>> client_ssl_stream_;
    boost::beast::flat_static_buffer<8192> buffer_;
    std::optional<http::request_parser<http::string_body>> parser_;

public:
    explicit ProxySession(tcp::socket socket) 
        : client_socket_(std::move(socket)) {}

    void start() {
        parser_.emplace();
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
        
        if (req.method() == http::verb::connect) {
            std::string domain = host_header;
            if (size_t pos = domain.find(':'); pos != std::string::npos) {
                domain = domain.substr(0, pos);
            }
            std::cout << "\n[MITM] Intercepted CONNECT to: " << domain << "\n";
            send_connect_ok(domain);
            return;
        }
        close();
    }

    void send_connect_ok(const std::string& domain) {
        auto self = shared_from_this();
        auto response = std::make_shared<std::string>("HTTP/1.1 200 Connection Established\r\n\r\n");
        
        asio::async_write(client_socket_, asio::buffer(*response),
            [self, domain](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    std::string crt_path, key_path;
                    if (!CertManager::prepare_cert_for_domain(domain, crt_path, key_path)) {
                        std::cerr << "[MITM] Failed to generate cert for " << domain << "\n";
                        self->close();
                        return;
                    }

                    auto session_ctx = std::make_shared<ssl::context>(ssl::context::tls_server);
                    session_ctx->set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 | ssl::context::no_sslv3);
                    session_ctx->use_certificate_chain_file(crt_path);
                    session_ctx->use_private_key_file(key_path, ssl::context::pem);

                    self->client_ssl_stream_.emplace(self->client_socket_, *session_ctx);
                    self->client_ssl_stream_->async_handshake(ssl::stream_base::server,
                        [self](boost::system::error_code ec) {
                            if (!ec) self->read_decrypted_request();
                            else self->close();
                        });
                } else self->close();
            });
    }

    void read_decrypted_request() {
        auto self = shared_from_this();
        parser_.emplace();
        http::async_read(*client_ssl_stream_, buffer_, *parser_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    auto req = self->parser_->get();
                    std::cout << "[MITM] SUCCESS! Decrypted request: " << req.method_string() << " " << req.target() << "\n";
                    self->send_fake_ssl_response();
                } else self->close();
            });
    }

    void send_fake_ssl_response() {
        auto self = shared_from_this();
        auto res = std::make_shared<http::response<http::string_body>>(http::status::ok, 11);
        res->set(http::field::server, "MyMITMProxy");
        res->set(http::field::content_type, "text/html");
        res->body() = "<h1>Hello from MITM Proxy!</h1><p>I decrypted your HTTPS traffic dynamically!</p>";
        res->prepare_payload();

        http::async_write(*client_ssl_stream_, *res,
            [self, res](boost::system::error_code ec, std::size_t) {
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