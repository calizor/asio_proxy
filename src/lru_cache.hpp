#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <ctime>
#include <list>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

// ─────────────────────────────────────────────────────────────────────────────
//  cache_control — вспомогательные функции для разбора HTTP-заголовков
//  Cache-Control, Pragma, Expires и вычисления TTL ответа по RFC 7234.
// ─────────────────────────────────────────────────────────────────────────────
namespace cache_control {

namespace detail {

// Проверяет наличие токена-директивы в заголовке (case-insensitive).
// Учитывает границы токенов: 'private' не совпадёт внутри 'no-private-cache'.
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

// Извлекает числовое значение директивы вида "directive=N" из заголовка.
// Возвращает -1, если директива не найдена или значение нечитаемо.
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

// Возвращает true, если запрос требует обойти кэш (no-cache, no-store
// или max-age=0 в Cache-Control запроса, либо Pragma: no-cache).
// Это означает «не используй кэшированную копию для этого запроса» — НЕ
// удаление записи из хранилища.
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

// Возвращает true, если ответ разрешено сохранять в кэше.
//
// По RFC 7234 §3 хранение запрещают только no-store и (для shared-кэша)
// private. Директивы no-cache и must-revalidate РАЗРЕШАЮТ хранение — они
// лишь требуют ревалидации перед использованием.
//
// Pragma: no-cache по RFC относится к запросам, не ответам, но многие
// серверы шлют его в ответах — трактуем мягко (как no-cache, т.е. храним).
inline bool response_is_storable(std::string_view cache_control_hdr,
                                 std::string_view /*pragma_hdr*/ = {}) {
    using detail::has_token;
    if (has_token(cache_control_hdr, "no-store")) return false;
    if (has_token(cache_control_hdr, "private"))  return false;
    return true;
}

// Возвращает TTL в секундах из s-maxage / max-age, либо -1 если не указано.
// s-maxage имеет приоритет (по RFC он адресован именно shared-кэшам).
inline long max_age_seconds(std::string_view cache_control_hdr) {
    long smaxage = detail::parse_seconds(cache_control_hdr, "s-maxage");
    if (smaxage >= 0) return smaxage;
    return detail::parse_seconds(cache_control_hdr, "max-age");
}

// Парсит HTTP-дату формата RFC 7231 §7.1.1.1 (например
// "Sun, 06 Nov 1994 08:49:37 GMT"). Поддерживает три исторических формата:
// IMF-fixdate, RFC 850, и asctime. Возвращает -1 при ошибке разбора.
inline std::time_t parse_http_date(std::string_view date_hdr) {
    if (date_hdr.empty()) return -1;
    std::tm tm{};
    std::string s(date_hdr);
    if (strptime(s.c_str(), "%a, %d %b %Y %H:%M:%S GMT", &tm) == nullptr &&
        strptime(s.c_str(), "%A, %d-%b-%y %H:%M:%S GMT", &tm) == nullptr &&
        strptime(s.c_str(), "%a %b %d %H:%M:%S %Y",      &tm) == nullptr) {
        return -1;
    }
#if defined(_WIN32)
    return _mkgmtime(&tm);
#else
    return timegm(&tm);
#endif
}

// Вычисляет TTL ответа в секундах, опираясь на:
//   1) max-age / s-maxage в Cache-Control (самый высокий приоритет),
//   2) Expires относительно Date,
//   3) эвристику 10% от (Date − Last-Modified), ограниченную сверху,
//   4) дефолтный TTL, если выше ничего не сработало.
//
// По RFC 7234 §4.2.2 эвристическое кэширование допустимо в отсутствие
// явных директив. Возвращает: >0 — ограниченное время, 0 — не кэшировать.
inline long compute_ttl_seconds(std::string_view cache_control_hdr,
                                std::string_view expires_hdr,
                                std::string_view date_hdr,
                                std::string_view last_modified_hdr,
                                long default_heuristic_ttl = 300,    // 5 минут
                                long max_heuristic_ttl     = 86400)  // 1 сутки
{
    // 1. max-age / s-maxage — высший приоритет.
    long ma = max_age_seconds(cache_control_hdr);
    if (ma > 0)  return ma;
    if (ma == 0) return 0;  // явный max-age=0 — не кэшируем

    // 2. Expires относительно Date (или текущего времени, если Date нет).
    if (!expires_hdr.empty()) {
        std::time_t exp = parse_http_date(expires_hdr);
        if (exp > 0) {
            std::time_t base = parse_http_date(date_hdr);
            if (base <= 0) base = std::time(nullptr);
            long delta = static_cast<long>(exp - base);
            if (delta > 0) return delta;
            return 0;
        }
    }

    // 3. Эвристика по Last-Modified: 10% от возраста ресурса.
    if (!last_modified_hdr.empty()) {
        std::time_t lm = parse_http_date(last_modified_hdr);
        if (lm > 0) {
            std::time_t base = parse_http_date(date_hdr);
            if (base <= 0) base = std::time(nullptr);
            long age = static_cast<long>(base - lm);
            if (age > 0) {
                long ttl = age / 10;
                if (ttl > max_heuristic_ttl) ttl = max_heuristic_ttl;
                if (ttl < 60) ttl = 60;  // меньше минуты — бессмысленно
                return ttl;
            }
        }
    }

    // 4. Дефолтный эвристический TTL — лучше короткий, чем бесконечный.
    return default_heuristic_ttl;
}

}  // namespace cache_control

// Возвращает true для статусов, которые по RFC 7231 §6.1 разрешено
// кэшировать эвристически (без явного Cache-Control/Expires).
inline bool is_heuristically_cacheable_status(int status) {
    switch (status) {
        case 200: case 203: case 204: case 206:
        case 300: case 301: case 308:
        case 404: case 405: case 410: case 414:
        case 501:
            return true;
        default:
            return false;
    }
}

// Статусы, которые кэшируемы только при явных директивах max-age/Expires.
// Это 302 и 307 — динамические редиректы.
inline bool is_cacheable_status_with_directives(int status) {
    return status == 302 || status == 307;
}

// Финальный классификатор: можно ли кэшировать ответ с данным статусом
// и заголовками. true → можно хранить, false → проксируем без кэша.
inline bool is_cacheable_status(int status,
                                std::string_view cache_control_hdr,
                                std::string_view expires_hdr) {
    if (is_heuristically_cacheable_status(status)) return true;
    if (is_cacheable_status_with_directives(status)) {
        if (cache_control::max_age_seconds(cache_control_hdr) > 0) return true;
        if (!expires_hdr.empty())                                  return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  CacheEntry — одна запись в кэше с опциональным временем жизни (TTL).
//  Если has_ttl == false, запись бессрочна (живёт пока не вытесняется
//  LRU-политикой).
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
//  LRUCache — потокобезопасный LRU-кэш с поддержкой TTL.
//
//  Особенности реализации:
//   - shared_mutex: get берёт shared-лок для первичной проверки наличия
//     ключа (несколько читателей не блокируют друг друга), а exclusive-лок
//     нужен только для splice-в-голову и удаления.
//   - TTL: устаревшие записи удаляются лениво при первом обращении.
//   - invalidate(key): точечное удаление — на случай если ответ от сервера
//     стал заведомо неактуальным (например, после POST/PUT/DELETE).
//
//  Сложность: get/put — O(1) в среднем (unordered_map + list::splice).
// ─────────────────────────────────────────────────────────────────────────────
class LRUCache {
    using List     = std::list<std::pair<std::string, CacheEntry>>;
    using Iterator = List::iterator;
    using Map      = std::unordered_map<std::string, Iterator>;

   public:
    explicit LRUCache(std::size_t capacity) : capacity_(capacity) {}

    // ── put ──────────────────────────────────────────────────────────────────
    // Кладёт значение по ключу. Если ключ уже есть — обновляет значение и
    // перемещает в голову списка. ttl=0 означает «бессрочно».
    void put(const std::string& key, const std::string& value,
             std::chrono::seconds ttl = std::chrono::seconds{0}) {
        CacheEntry entry;
        entry.value   = value;
        entry.has_ttl = (ttl.count() > 0);
        if (entry.has_ttl)
            entry.expires = std::chrono::steady_clock::now() + ttl;

        std::unique_lock lock(mutex_);

        // Обновление существующей записи.
        auto it = map_.find(key);
        if (it != map_.end()) {
            it->second->second = std::move(entry);
            list_.splice(list_.begin(), list_, it->second);
            return;
        }

        // Вытеснение по LRU при переполнении.
        if (list_.size() >= capacity_) {
            map_.erase(list_.back().first);
            list_.pop_back();
        }

        list_.emplace_front(key, std::move(entry));
        map_[key] = list_.begin();
    }

    // ── get ──────────────────────────────────────────────────────────────────
    // Возвращает значение по ключу, обновляя позицию записи в LRU.
    // nullopt — если ключа нет или запись протухла.
    std::optional<std::string> get(const std::string& key) {
        // Шаг 1: shared-лок для дешёвой проверки наличия.
        {
            std::shared_lock lock(mutex_);
            auto it = map_.find(key);
            if (it == map_.end())
                return std::nullopt;  // промах
        }

        // Шаг 2: exclusive-лок — нужен для возможной модификации (splice
        // в голову или удаление протухшей записи).
        std::unique_lock lock(mutex_);

        // Повторная проверка: между шагами 1 и 2 другой поток мог удалить.
        auto it = map_.find(key);
        if (it == map_.end()) return std::nullopt;

        // Протухшая запись — удаляем и считаем промахом.
        if (it->second->second.is_expired()) {
            list_.erase(it->second);
            map_.erase(it);
            return std::nullopt;
        }

        // Помечаем как недавно использованную: переносим в голову списка.
        list_.splice(list_.begin(), list_, it->second);
        return it->second->second.value;
    }

    // ── invalidate ───────────────────────────────────────────────────────────
    // Точечное удаление записи по ключу. Возвращает true, если запись была.
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
    std::size_t               capacity_;
    List                      list_;   // от MRU (голова) до LRU (хвост)
    Map                       map_;    // ключ → итератор узла списка, O(1)
    mutable std::shared_mutex mutex_;
};
