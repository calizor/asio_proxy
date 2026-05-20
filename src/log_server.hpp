#pragma once

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <nlohmann/json.hpp>
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
using json          = nlohmann::json;

static constexpr size_t BODY_MAX_BYTES = 65536; // 64 KB

// Returns true if Content-Type is textual and worth capturing
static inline bool is_text_content_type(const std::string& ct) {
    if (ct.find("text/")                  != std::string::npos) return true;
    if (ct.find("application/json")       != std::string::npos) return true;
    if (ct.find("application/javascript") != std::string::npos) return true;
    if (ct.find("application/xml")        != std::string::npos) return true;
    if (ct.find("application/xhtml")      != std::string::npos) return true;
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  LogEntry — one row in the web panel (like a Wireshark packet)
// ─────────────────────────────────────────────────────────────────────────────
struct LogEntry {
    uint64_t    id           = 0;
    std::string timestamp;
    std::string type;         // CONNECT | MITM | TUNNEL | CACHE_HIT | CACHE_MISS | RESPONSE | TIMEOUT | ERROR
    std::string method;       // GET / POST / CONNECT / …
    std::string domain;
    std::string path;
    int         status       = 0;   // HTTP status (0 = none)
    std::string info;
    size_t      bytes        = 0;
    double      latency_ms   = 0.0;
    std::string content_type;
    std::string body;               // text bodies only, max BODY_MAX_BYTES
    bool        body_truncated = false;

    std::string to_json() const {
        json j = {
            {"id",             id},
            {"timestamp",      timestamp},
            {"type",           type},
            {"method",         method},
            {"domain",         domain},
            {"path",           path},
            {"status",         status},
            {"info",           info},
            {"bytes",          bytes},
            {"latency_ms",     latency_ms},
            {"content_type",   content_type},
            {"body",           body},
            {"body_truncated", body_truncated},
        };
        // ensure_ascii=true replaces invalid UTF-8 bytes with \uFFFD instead of throwing
        return j.dump(-1, ' ', true);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
//  LogServer — singleton WebSocket server (default port 8081).
//
//  Usage from anywhere in the proxy:
//      LogServer::instance().log_connect("github.com");
//      LogServer::instance().log_response("github.com", "/", 200, 4096, 55.3);
// ─────────────────────────────────────────────────────────────────────────────
class LogServer : public std::enable_shared_from_this<LogServer> {
    // ── WebSocket session (one per connected browser tab) ────────────────────
    struct WsSession : public std::enable_shared_from_this<WsSession> {
        websocket::stream<tcp::socket> ws_;
        std::deque<std::string>        queue_;   // outgoing message queue
        bool                           writing_ = false;
        std::mutex                     mu_;

        explicit WsSession(tcp::socket socket) : ws_(std::move(socket)) {}

        // Send history snapshot, then start relaying live events
        void start(std::vector<std::string> snapshot) {
            ws_.set_option(websocket::stream_base::decorator([](websocket::response_type& res) {
                res.set(beast::http::field::server, "ProxyPanel/1.0");
            }));
            ws_.read_message_max(4 * 1024 * 1024);

            auto self = shared_from_this();
            ws_.async_accept([self, snap = std::move(snapshot)](beast::error_code ec) mutable {
                if (ec) return;
                for (auto& msg : snap) self->enqueue(msg);
                self->keep_alive_read();
            });
        }

        void enqueue(const std::string& msg) {
            std::lock_guard<std::mutex> lk(mu_);
            queue_.push_back(msg);
            if (!writing_) flush();
        }

    private:
        // Drain the outgoing queue one message at a time
        void flush() {
            if (queue_.empty()) { writing_ = false; return; }
            writing_   = true;
            auto self  = shared_from_this();
            auto buf   = std::make_shared<std::string>(std::move(queue_.front()));
            queue_.pop_front();
            ws_.async_write(asio::buffer(*buf), [self, buf](beast::error_code ec, std::size_t) {
                std::lock_guard<std::mutex> lk(self->mu_);
                if (ec) { self->writing_ = false; return; }
                self->flush();
            });
        }

        // Keep the connection alive (browser never sends anything, but we still need to read)
        void keep_alive_read() {
            auto self = shared_from_this();
            auto buf  = std::make_shared<beast::flat_buffer>();
            ws_.async_read(*buf, [self, buf](beast::error_code ec, std::size_t) {
                if (!ec) self->keep_alive_read();
            });
        }
    };

    // ── LogServer state ──────────────────────────────────────────────────────
    tcp::acceptor                           acceptor_;
    std::mutex                              history_mu_;
    std::deque<std::string>                 history_;        // last N serialised entries
    static constexpr size_t                 MAX_HISTORY = 500;
    std::atomic<uint64_t>                   counter_{1};
    std::mutex                              sessions_mu_;
    std::vector<std::shared_ptr<WsSession>> sessions_;

public:
    LogServer(asio::io_context& ctx, unsigned short port)
        : acceptor_(ctx, {tcp::v4(), port}) {}

    // ── Singleton access ─────────────────────────────────────────────────────
    static LogServer& instance() { return *singleton(); }

    static void init(asio::io_context& ctx, unsigned short port = 8081) {
        singleton() = std::make_shared<LogServer>(ctx, port);
        singleton()->accept_loop();
        std::cout << "[LogServer] web panel listening on ws://localhost:" << port << "\n";
    }

    // Must be called after ioc.stop() and thread join, but BEFORE ioc destructor.
    // Releases the acceptor and all sessions so they don't outlive io_context.
    static void shutdown() {
        singleton().reset();
    }

    // ── Core log method ──────────────────────────────────────────────────────
    void log(LogEntry entry) {
        entry.id        = counter_++;
        entry.timestamp = current_time();

        const std::string msg = entry.to_json();

        // Broadcast to every connected browser, prune dead sessions
        {
            std::lock_guard<std::mutex> lk(sessions_mu_);
            sessions_.erase(
                std::remove_if(sessions_.begin(), sessions_.end(),
                    [](const std::shared_ptr<WsSession>& s) { return !s->ws_.is_open(); }),
                sessions_.end());
            for (auto& s : sessions_) s->enqueue(msg);
        }

        // Keep a rolling history for late-joining browsers
        {
            std::lock_guard<std::mutex> lk(history_mu_);
            history_.push_back(msg);
            if (history_.size() > MAX_HISTORY) history_.pop_front();
        }
    }

    // ── Convenience helpers ──────────────────────────────────────────────────
    void log_connect(const std::string& domain) {
        log({.type="CONNECT", .method="CONNECT", .domain=domain});
    }

    void log_mitm(const std::string& method, const std::string& domain, const std::string& path) {
        log({.type="MITM", .method=method, .domain=domain, .path=path, .info="intercepted"});
    }

    void log_cache_hit(const std::string& domain, const std::string& path) {
        log({.type="CACHE_HIT", .method="GET", .domain=domain, .path=path, .status=200, .info="from cache"});
    }

    void log_cache_miss(const std::string& domain) {
        log({.type="CACHE_MISS", .method="GET", .domain=domain});
    }

    void log_response(const std::string& domain, const std::string& path,
                      int status, size_t bytes, double ms,
                      const std::string& ct   = "",
                      const std::string& body = "",
                      bool truncated          = false) {
        log({
            .type          = "RESPONSE",
            .method        = "GET",
            .domain        = domain,
            .path          = path,
            .status        = status,
            .bytes         = bytes,
            .latency_ms    = ms,
            .content_type  = ct,
            .body          = body,
            .body_truncated = truncated,
        });
    }

    void log_timeout(const std::string& domain) {
        log({.type="TIMEOUT", .domain=domain});
    }

    void log_error(const std::string& domain, const std::string& err) {
        log({.type="ERROR", .domain=domain, .info=err});
    }

private:
    // ── Accept loop ──────────────────────────────────────────────────────────
    void accept_loop() {
        auto self = shared_from_this();
        acceptor_.async_accept([self](beast::error_code ec, tcp::socket socket) {
            if (!ec) {
                // Give the new client a copy of recent history
                std::vector<std::string> snapshot;
                {
                    std::lock_guard<std::mutex> lk(self->history_mu_);
                    snapshot.assign(self->history_.begin(), self->history_.end());
                }

                auto session = std::make_shared<WsSession>(std::move(socket));
                {
                    std::lock_guard<std::mutex> lk(self->sessions_mu_);
                    self->sessions_.push_back(session);
                }
                session->start(std::move(snapshot));
            }
            self->accept_loop(); // keep accepting
        });
    }

    // ── Singleton storage ────────────────────────────────────────────────────
    static std::shared_ptr<LogServer>& singleton() {
        static std::shared_ptr<LogServer> ptr;
        return ptr;
    }

    // ── Timestamp helper ─────────────────────────────────────────────────────
    static std::string current_time() {
        auto now  = std::chrono::system_clock::now();
        auto ms   = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        auto time = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &time);
#else
        localtime_r(&time, &tm);
#endif
        std::ostringstream ss;
        ss << std::put_time(&tm, "%H:%M:%S")
           << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }
};
