#pragma once

#include <boost/asio.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "lru_cache.hpp"
#include "mitm_session.hpp"
#include "tunnel_session.hpp"

namespace asio = boost::asio;
namespace http = boost::beast::http;
using tcp      = asio::ip::tcp;

// ConnectionHandler — точка входа для каждого нового соединения.
// Читает один HTTP-заголовок, определяет тип соединения (CONNECT vs plain HTTP),
// отправляет "200 Connection Established" и передаёт управление
// MitmSession (MITM) или TunnelSession (слепой туннель).

class ConnectionHandler : public std::enable_shared_from_this<ConnectionHandler> {
    tcp::socket               client_socket_;
    boost::beast::flat_buffer buffer_;
    http::request_parser<http::string_body> parser_;
    std::shared_ptr<LRUCache> cache_;

   public:
    ConnectionHandler(tcp::socket socket, std::shared_ptr<LRUCache> cache)
        : client_socket_(std::move(socket)), cache_(std::move(cache)) {}

    void start() {
        auto self = shared_from_this();
        http::async_read_header(
            client_socket_, buffer_, parser_,
            [self](boost::system::error_code ec, std::size_t) {
                if (!ec)
                    self->dispatch();
            });
    }

   private:
    void dispatch() {
        auto req = parser_.get();

        if (req.method() != http::verb::connect)
            return;

        std::string domain = req[http::field::host];
        if (size_t pos = domain.find(':'); pos != std::string::npos)
            domain.resize(pos);

        if (is_mitm_domain(domain)) {
            send_connect_ok_then<MitmSession>(std::move(domain));
        } else {
            send_connect_ok_then<TunnelSession>(std::move(domain));
        }
    }

    template <typename Session>
    void send_connect_ok_then(std::string domain) {
        auto self     = shared_from_this();
        auto response = std::make_shared<std::string>("HTTP/1.1 200 Connection Established\r\n\r\n");

        asio::async_write(
            client_socket_, asio::buffer(*response),
            [self, response, domain = std::move(domain)](boost::system::error_code ec, std::size_t) mutable {
                if (!ec)
                    std::make_shared<Session>(std::move(self->client_socket_), std::move(domain), self->cache_)->start();
            });
    }

    // Возвращает true если домен входит в suffix-список (точное совпадение или поддомен).
    static bool matches_any(const std::string& domain, const std::vector<std::string>& suffixes) {
        for (const auto& s : suffixes) {
            if (domain == s)
                return true;
            // "cdn.gosuslugi.ru" совпадает с суффиксом "gosuslugi.ru" через точку
            if (domain.size() > s.size() &&
                domain[domain.size() - s.size() - 1] == '.' &&
                domain.compare(domain.size() - s.size(), s.size(), s) == 0)
                return true;
        }
        return false;
    }

    bool is_mitm_domain(const std::string& domain) {
        // ---------------------------------------------------------------
        // Группы доменов для MITM-перехвата.
        // Каждая группа — это один логический сервис плюс все домены,
        // с которых он подгружает ресурсы (CDN, API, статика, аналитика).
        // ---------------------------------------------------------------
        static const std::vector<std::vector<std::string>> mitm_groups = {
            // --- Госуслуги ---
            // Основной портал + все домены раздачи ресурсов
            {
                "gosuslugi.ru",       // основной портал
                "esia.gosuslugi.ru",  // авторизация (ЕСИА)
                "lk.gosuslugi.ru",    // личный кабинет
                "static.gosuslugi.ru",
                "cdn.gosuslugi.ru",
                "pgu.gosuslugi.ru",
                "beta.gosuslugi.ru",
            },
            // --- Добавляй новые группы сюда ---
            // {
            //     "example.ru",
            //     "static.example.ru",
            //     "api.example.ru",
            // },
            {
                "cfuv.ru"
            }
        };

        // ---------------------------------------------------------------
        // Домены, которые всегда идут через слепой туннель.
        // Проверяется ПОСЛЕ групп — если домен есть в группе, но
        // также есть в tunnel_list, туннель побеждает (безопаснее).
        // ---------------------------------------------------------------
        static const std::vector<std::string> tunnel_list = {
            // Финансы и платежи
            "paypal.com",
            "stripe.com",
            "visa.com",
            "mastercard.com",
            // Почта
            "gmail.com",
            "outlook.com",
            "mail.ru",
            // Обновления / телеметрия ОС
            "windowsupdate.com",
            "apple.com",
            "ocsp.digicert.com",
            "ocsp.pki.goog",
            // Certificate pinning — сломается при MITM
            "accounts.google.com",
            "login.microsoftonline.com",
        };

        // Явный туннель имеет приоритет
        if (matches_any(domain, tunnel_list))
            return false;

        // Проверяем каждую MITM-группу
        for (const auto& group : mitm_groups) {
            if (matches_any(domain, group))
                return true;
        }

        // Всё остальное — туннель (безопасный дефолт)
        return false;
    }
};