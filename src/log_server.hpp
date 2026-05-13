#pragma once

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <chrono>
#include <deque>
#include <iomanip>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace asio      = boost::asio;
namespace beast     = boost::beast;
namespace websocket = beast::websocket;
using tcp           = asio::ip::tcp;

// Экранирует строку для вставки в JSON-значение
static inline std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    for (unsigned char c : s) {
        if      (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (c < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\u%04x", c);
            out += buf;
        } else {
            out += static_cast<char>(c);
        }
    }
    out += '"';
    return out;
}

// ──────────────────────────────────────────────
//  Структура одной записи лога
// ──────────────────────────────────────────────
struct LogEntry {
    uint64_t    id         = 0;
    std::string timestamp;
    std::string type;
    std::string method;
    std::string domain;
    std::string path;
    int         status     = 0;
    std::string info;
    size_t      bytes      = 0;
    double      latency_ms = 0.0;

    std::string to_json() const {
        std::ostringstream o;
        o << std::fixed;
        o << '{'
          << "\"id\":"         << id                     << ','
          << "\"timestamp\":"  << json_escape(timestamp) << ','
          << "\"type\":"       << json_escape(type)      << ','
          << "\"method\":"     << json_escape(method)    << ','
          << "\"domain\":"     << json_escape(domain)    << ','
          << "\"path\":"       << json_escape(path)      << ','
          << "\"status\":"     << status                 << ','
          << "\"info\":"       << json_escape(info)      << ','
          << "\"bytes\":"      << bytes                  << ','
          << "\"latency_ms\":" << latency_ms
          << '}';
        return o.str();
    }
};

// ──────────────────────────────────────────────
//  LogServer — singleton, WebSocket-сервер на порту 8081
// ──────────────────────────────────────────────
class LogServer : public std::enable_shared_from_this<LogServer> {
    tcp::acceptor            acceptor_;
    std::mutex               history_mu_;
    std::deque<std::string>  history_;
    static constexpr size_t  MAX_HISTORY = 500;
    std::atomic<uint64_t>    counter_{1};

    struct WsSession : public std::enable_shared_from_this<WsSession> {
        websocket::stream<tcp::socket> ws_;
        std::deque<std::string>        send_queue_;
        bool                           writing_ = false;
        std::mutex                     mu_;

        explicit WsSession(tcp::socket s) : ws_(std::move(s)) {}

        void start(std::vector<std::string> snapshot) {
            ws_.set_option(websocket::stream_base::decorator([](websocket::response_type& res) {
                res.set(beast::http::field::server, "ProxyPanel/1.0");
            }));
            auto self = shared_from_this();
            ws_.async_accept([self, snap = std::move(snapshot)](beast::error_code ec) mutable {
                if (ec) return;
                for (auto& msg : snap) self->send(msg);
                self->do_read();
            });
        }

        void send(const std::string& msg) {
            std::lock_guard<std::mutex> lk(mu_);
            send_queue_.push_back(msg);
            if (!writing_) pump();
        }

        void pump() {
            if (send_queue_.empty()) { writing_ = false; return; }
            writing_  = true;
            auto self = shared_from_this();
            auto buf  = std::make_shared<std::string>(std::move(send_queue_.front()));
            send_queue_.pop_front();
            ws_.async_write(asio::buffer(*buf), [self, buf](beast::error_code ec, std::size_t) {
                std::lock_guard<std::mutex> lk(self->mu_);
                if (ec) { self->writing_ = false; return; }
                self->pump();
            });
        }

        void do_read() {
            auto self = shared_from_this();
            auto buf  = std::make_shared<beast::flat_buffer>();
            ws_.async_read(*buf, [self, buf](beast::error_code ec, std::size_t) {
                if (!ec) self->do_read();
            });
        }
    };

    std::mutex                              sessions_mu_;
    std::vector<std::shared_ptr<WsSession>> sessions_;

   public:
    LogServer(asio::io_context& ctx, unsigned short port)
        : acceptor_(ctx, {tcp::v4(), port}) {}

    static LogServer& instance() { return *instance_ptr(); }

    static void init(asio::io_context& ctx, unsigned short port = 8081) {
        instance_ptr() = std::make_shared<LogServer>(ctx, port);
        instance_ptr()->do_accept();
        std::cout << "[LogServer] WebSocket панель на ws://localhost:" << port << "\n";
    }

   private:
    static std::shared_ptr<LogServer>& instance_ptr() {
        static std::shared_ptr<LogServer> ptr;
        return ptr;
    }

    void do_accept() {
        auto self = shared_from_this();
        acceptor_.async_accept([self](beast::error_code ec, tcp::socket sock) {
            if (!ec) {
                std::vector<std::string> snapshot;
                {
                    std::lock_guard<std::mutex> lk(self->history_mu_);
                    snapshot.assign(self->history_.begin(), self->history_.end());
                }
                auto session = std::make_shared<WsSession>(std::move(sock));
                {
                    std::lock_guard<std::mutex> lk(self->sessions_mu_);
                    self->sessions_.push_back(session);
                }
                session->start(std::move(snapshot));
            }
            self->do_accept();
        });
    }

   public:
    void log(LogEntry entry) {
        entry.id        = counter_++;
        entry.timestamp = current_timestamp();
        std::string msg = entry.to_json();

        {
            std::lock_guard<std::mutex> lk(sessions_mu_);
            sessions_.erase(
                std::remove_if(sessions_.begin(), sessions_.end(),
                               [](const std::shared_ptr<WsSession>& s) {
                                   return !s->ws_.is_open();
                               }),
                sessions_.end());
            for (auto& s : sessions_) s->send(msg);
        }

        std::lock_guard<std::mutex> lk(history_mu_);
        history_.push_back(std::move(msg));
        if (history_.size() > MAX_HISTORY) history_.pop_front();
    }

    void log_connect(const std::string& domain) {
        log({0, "", "CONNECT", "CONNECT", domain, "", 0, "", 0, 0.0});
    }
    void log_mitm(const std::string& method, const std::string& domain, const std::string& path) {
        log({0, "", "MITM", method, domain, path, 0, "intercepted", 0, 0.0});
    }
    void log_cache_hit(const std::string& domain, const std::string& path) {
        log({0, "", "CACHE_HIT", "GET", domain, path, 200, "from cache", 0, 0.0});
    }
    void log_cache_miss(const std::string& domain) {
        log({0, "", "CACHE_MISS", "GET", domain, "", 0, "", 0, 0.0});
    }
    void log_response(const std::string& domain, const std::string& path, int status, size_t bytes, double ms) {
        log({0, "", "RESPONSE", "GET", domain, path, status, "", bytes, ms});
    }
    void log_timeout(const std::string& domain) {
        log({0, "", "TIMEOUT", "", domain, "", 0, "", 0, 0.0});
    }
    void log_error(const std::string& domain, const std::string& err) {
        log({0, "", "ERROR", "", domain, "", 0, err, 0, 0.0});
    }

   private:
    static std::string current_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                       now.time_since_epoch()) % 1000;
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tm_info{};
#ifdef _WIN32
        localtime_s(&tm_info, &t);
#else
        localtime_r(&t, &tm_info);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm_info, "%H:%M:%S")
            << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return oss.str();
    }
};
