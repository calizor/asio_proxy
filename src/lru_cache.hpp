#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <list>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

// ─────────────────────────────────────────────────────────────────────────────
//  cache_control — вспомогательные функции для разбора заголовков
// ─────────────────────────────────────────────────────────────────────────────
namespace cache_control {

namespace detail {

inline bool has_token(std::string_view header, std::string_view token) {
    std::string lhdr(header.size(), '\0');
    std::transform(header.begin(), header.end(), lhdr.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::size_t pos = 0;
    while ((pos = lhdr.find(token, pos)) != std::string::npos) {
        bool left_ok  = (pos == 0) || lhdr[pos - 1] == ',' || lhdr[pos - 1] == ' ';
        std::size_t after = pos + token.size();
        bool right_ok = (after >= lhdr.size()) ||
                        lhdr[after] == ',' || lhdr[after] == ' ' ||
                        lhdr[after] == '=' || lhdr[after] == ';';
        if (left_ok && right_ok) return true;
        pos += token.size();
    }
    return false;
}

inline long parse_seconds(std::string_view header, std::string_view directive) {
    std::string lhdr(header.size(), '\0');
    std::transform(header.begin(), header.end(), lhdr.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::string needle(directive);
    needle += '=';
    auto pos = lhdr.find(needle);
    if (pos == std::string::npos) return -1;

    pos += needle.size();
    while (pos < lhdr.size() && lhdr[pos] == ' ') ++pos;

    char* end = nullptr;
    long  val = std::strtol(lhdr.c_str() + pos, &end, 10);
    return (end > lhdr.c_str() + pos) ? val : -1L;
}

}  // namespace detail

/// Возвращает true если запрос требует свежего ответа — кэш нужно обойти.
inline bool request_bypasses_cache(std::string_view cache_control_hdr,
                                   std::string_view pragma_hdr = {}) {
    using detail::has_token;
    using detail::parse_seconds;
    if (has_token(cache_control_hdr, "no-cache"))         return true;
    if (has_token(cache_control_hdr, "no-store"))         return true;
    if (parse_seconds(cache_control_hdr, "max-age") == 0) return true;
    if (has_token(pragma_hdr,         "no-cache"))        return true;
    return false;
}

/// Возвращает true если ответ разрешено сохранять в кэше.
inline bool response_is_storable(std::string_view cache_control_hdr,
                                 std::string_view pragma_hdr = {}) {
    using detail::has_token;
    if (has_token(cache_control_hdr, "no-store"))        return false;
    if (has_token(cache_control_hdr, "no-cache"))        return false;
    if (has_token(cache_control_hdr, "private"))         return false;
    if (has_token(cache_control_hdr, "must-revalidate")) return false;
    if (has_token(pragma_hdr,        "no-cache"))        return false;
    return true;
}

/// Возвращает TTL в секундах из s-maxage / max-age, либо -1 если нет.
inline long max_age_seconds(std::string_view cache_control_hdr) {
    long smaxage = detail::parse_seconds(cache_control_hdr, "s-maxage");
    if (smaxage >= 0) return smaxage;
    return detail::parse_seconds(cache_control_hdr, "max-age");
}

}  // namespace cache_control

// ─────────────────────────────────────────────────────────────────────────────
//  CacheEntry — хранимая запись с опциональным временем жизни (TTL)
// ─────────────────────────────────────────────────────────────────────────────
struct CacheEntry {
    std::string                           value;
    std::chrono::steady_clock::time_point expires;
    bool                                  has_ttl = false;

    bool is_expired() const {
        return has_ttl && (std::chrono::steady_clock::now() > expires);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
//  LRUCache — потокобезопасный LRU-кэш с TTL и поддержкой Cache-Control.
//
//  Улучшения по сравнению с базовой реализацией:
//   1. shared_mutex: операция get берёт shared лок — несколько потоков
//      читают одновременно без блокировки друг друга.
//      Только put/invalidate берут exclusive лок.
//   2. TTL: записи автоматически устаревают по истечении срока.
//      Удаляются лениво при следующем обращении к ключу.
//   3. invalidate(key): точечное удаление для Cache-Control: no-cache.
// ─────────────────────────────────────────────────────────────────────────────
class LRUCache {
    using List     = std::list<std::pair<std::string, CacheEntry>>;
    using Iterator = List::iterator;
    using Map      = std::unordered_map<std::string, Iterator>;

public:
    explicit LRUCache(std::size_t capacity) : capacity_(capacity) {}

    // ── put ──────────────────────────────────────────────────────────────────
    void put(const std::string& key, const std::string& value,
             std::chrono::seconds ttl = std::chrono::seconds{0}) {
        CacheEntry entry;
        entry.value   = value;
        entry.has_ttl = (ttl.count() > 0);
        if (entry.has_ttl)
            entry.expires = std::chrono::steady_clock::now() + ttl;

        std::unique_lock lock(mutex_);

        auto it = map_.find(key);
        if (it != map_.end()) {
            it->second->second = std::move(entry);
            list_.splice(list_.begin(), list_, it->second);
            return;
        }

        if (list_.size() >= capacity_) {
            map_.erase(list_.back().first);
            list_.pop_back();
        }

        list_.emplace_front(key, std::move(entry));
        map_[key] = list_.begin();
    }

    // ── get ──────────────────────────────────────────────────────────────────
    std::optional<std::string> get(const std::string& key) {
        // Шаг 1: shared лок — проверяем наличие ключа без блокировки писателей
        {
            std::shared_lock lock(mutex_);
            auto it = map_.find(key);
            if (it == map_.end())
                return std::nullopt;  // промах
        }

        // Шаг 2: exclusive лок — удаляем протухшее или поднимаем в голову
        std::unique_lock lock(mutex_);

        // Повторная проверка: другой поток мог удалить запись пока мы ждали лок
        auto it = map_.find(key);
        if (it == map_.end())
            return std::nullopt;

        if (it->second->second.is_expired()) {
            list_.erase(it->second);
            map_.erase(it);
            return std::nullopt;
        }

        // Перемещаем в голову списка (отмечаем как недавно использованный)
        list_.splice(list_.begin(), list_, it->second);
        return it->second->second.value;
    }

    // ── invalidate ───────────────────────────────────────────────────────────
    bool invalidate(const std::string& key) {
        std::unique_lock lock(mutex_);
        auto it = map_.find(key);
        if (it == map_.end()) return false;
        list_.erase(it->second);
        map_.erase(it);
        return true;
    }

    std::size_t size() const {
        std::shared_lock lock(mutex_);
        return map_.size();
    }

private:
    std::size_t        capacity_;
    List               list_;   // от MRU (голова) до LRU (хвост)
    Map                map_;    // ключ → итератор на узел списка, O(1) поиск
    mutable std::shared_mutex mutex_;
};