#pragma once

#include <chrono>
#include <cstddef>
#include <list>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <algorithm>

// ─────────────────────────────────────────────────────────────────────────────
//  cache_control — вспомогательные функции для разбора заголовков
//  Принимают значение заголовка (строку после двоеточия).
//
//  Пример использования:
//    std::string cc = std::string(req[http::field::cache_control]);
//    if (cache_control::request_bypasses_cache(cc)) cache_->invalidate(key);
// ─────────────────────────────────────────────────────────────────────────────
namespace cache_control {

namespace detail {

// Ищет токен директивы внутри значения заголовка Cache-Control.
// Учитывает разделители (, и пробел) чтобы не найти "no-cache" внутри "no-cache-extended".
inline bool has_token(std::string_view header, std::string_view token) {
    // Приводим заголовок к нижнему регистру для сравнения
    std::string lhdr(header.size(), '\0');
    std::transform(header.begin(), header.end(), lhdr.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::size_t pos = 0;
    while ((pos = lhdr.find(token, pos)) != std::string::npos) {
        // Слева должен быть разделитель или начало строки
        bool left_ok  = (pos == 0) || lhdr[pos - 1] == ',' || lhdr[pos - 1] == ' ';
        // Справа должен быть разделитель, '=', ';' или конец строки
        std::size_t after = pos + token.size();
        bool right_ok = (after >= lhdr.size()) ||
                        lhdr[after] == ',' || lhdr[after] == ' ' ||
                        lhdr[after] == '=' || lhdr[after] == ';';
        if (left_ok && right_ok) return true;
        pos += token.size();
    }
    return false;
}

// Парсит числовое значение директивы, например "max-age=300" → 300.
// Возвращает -1 если директива отсутствует.
inline long parse_seconds(std::string_view header, std::string_view directive) {
    std::string lhdr(header.size(), '\0');
    std::transform(header.begin(), header.end(), lhdr.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::string needle(directive);
    needle += '=';
    auto pos = lhdr.find(needle);
    if (pos == std::string::npos) return -1;

    pos += needle.size();
    while (pos < lhdr.size() && lhdr[pos] == ' ') ++pos;  // пропускаем пробелы

    char* end  = nullptr;
    long  val  = std::strtol(lhdr.c_str() + pos, &end, 10);
    return (end > lhdr.c_str() + pos) ? val : -1L;
}

}  // namespace detail

// ── Запросные директивы ──────────────────────────────────────────────────────

/// Возвращает true если запрос требует свежего ответа — кэш нужно обойти.
/// Покрывает: no-cache, no-store, max-age=0, Pragma: no-cache
inline bool request_bypasses_cache(std::string_view cache_control_hdr,
                                   std::string_view pragma_hdr = {}) {
    using detail::has_token;
    using detail::parse_seconds;
    if (has_token(cache_control_hdr, "no-cache"))        return true;
    if (has_token(cache_control_hdr, "no-store"))        return true;
    if (parse_seconds(cache_control_hdr, "max-age") == 0) return true;
    if (has_token(pragma_hdr,         "no-cache"))        return true;
    return false;
}

// ── Ответные директивы ───────────────────────────────────────────────────────

/// Возвращает true если ответ разрешено сохранять в кэше.
/// Блокирует: no-store, no-cache, private, must-revalidate, Pragma: no-cache
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

/// Возвращает TTL в секундах из max-age (или s-maxage), либо -1 если нет.
/// s-maxage имеет приоритет над max-age (предназначен для промежуточных кэшей).
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
    std::string                            value;
    std::chrono::steady_clock::time_point  expires;   // актуально только если has_ttl == true
    bool                                   has_ttl = false;

    /// Возвращает true если запись устарела и должна быть удалена.
    bool is_expired() const {
        return has_ttl && (std::chrono::steady_clock::now() > expires);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
//  LRUCache — потокобезопасный LRU-кэш с TTL и поддержкой Cache-Control.
//
//  Улучшения по сравнению с базовой реализацией:
//   1. shared_mutex вместо mutex:
//      операция get берёт shared (читающий) лок — несколько потоков
//      могут читать одновременно без блокировки друг друга.
//      Только put/invalidate берут exclusive (пишущий) лок.
//   2. TTL: записи автоматически считаются устаревшими по истечении срока.
//      Устаревшие записи удаляются лениво при следующем обращении к ключу.
//   3. invalidate(key): точечное удаление записи для обработки
//      Cache-Control: no-cache запросов.
// ─────────────────────────────────────────────────────────────────────────────
class LRUCache {
public:
    /// capacity — максимальное число записей в кэше.
    explicit LRUCache(std::size_t capacity) : capacity_(capacity) {}

    // ── put ──────────────────────────────────────────────────────────────────
    /// Добавить или обновить запись.
    /// ttl == 0 означает бессрочное хранение.
    void put(const std::string& key, const std::string& value,
             std::chrono::seconds ttl = std::chrono::seconds{0}) {

        CacheEntry entry;
        entry.value   = value;
        entry.has_ttl = (ttl.count() > 0);
        if (entry.has_ttl)
            entry.expires = std::chrono::steady_clock::now() + ttl;

        std::unique_lock lock(mutex_);  // эксклюзивный лок — пишем

        auto it = cache_map_.find(key);
        if (it != cache_map_.end()) {
            // Ключ уже есть — обновляем значение и перемещаем в голову списка
            it->second->second = std::move(entry);
            cache_list_.splice(cache_list_.begin(), cache_list_, it->second);
            return;
        }

        // Если кэш заполнен — вытесняем наименее используемый элемент (хвост)
        if (cache_list_.size() >= capacity_) {
            auto last = cache_list_.back();
            cache_map_.erase(last.first);
            cache_list_.pop_back();
        }

        // Вставляем новый элемент в голову (самый "свежий")
        cache_list_.emplace_front(key, std::move(entry));
        cache_map_[key] = cache_list_.begin();
    }

    // ── get ──────────────────────────────────────────────────────────────────
    /// Получить значение по ключу.
    /// Возвращает nullopt при промахе или если запись устарела.
    std::optional<std::string> get(const std::string& key) {
        // Сначала пробуем shared (читающий) лок — не блокирует другие get()
        {
            std::shared_lock lock(mutex_);
            auto it = cache_map_.find(key);
            if (it == cache_map_.end())
                return std::nullopt;  // промах — ключа нет
            if (it->second->second.is_expired())
                // Запись устарела — нужен эксклюзивный лок для удаления,
                // выходим из shared-блока и идём ниже
                goto remove_expired;
            // Нашли живую запись — но splice требует эксклюзивного лока,
            // переходим к блоку promote
            goto promote;
        }

    remove_expired: {
            std::unique_lock lock(mutex_);
            auto it = cache_map_.find(key);
            // Повторная проверка: другой поток мог уже удалить запись
            if (it != cache_map_.end() && it->second->second.is_expired()) {
                cache_list_.erase(it->second);
                cache_map_.erase(it);
            }
            return std::nullopt;
        }

    promote: {
            // Эксклюзивный лок для перемещения элемента в голову списка
            std::unique_lock lock(mutex_);
            auto it = cache_map_.find(key);
            if (it == cache_map_.end())
                return std::nullopt;
            if (it->second->second.is_expired()) {
                cache_list_.erase(it->second);
                cache_map_.erase(it);
                return std::nullopt;
            }
            cache_list_.splice(cache_list_.begin(), cache_list_, it->second);
            return it->second->second.value;
        }
    }

    // ── invalidate ───────────────────────────────────────────────────────────
    /// Удалить конкретный ключ из кэша.
    /// Используется при обработке Cache-Control: no-cache в запросе.
    bool invalidate(const std::string& key) {
        std::unique_lock lock(mutex_);
        auto it = cache_map_.find(key);
        if (it == cache_map_.end()) return false;
        cache_list_.erase(it->second);
        cache_map_.erase(it);
        return true;
    }

    /// Текущее число записей в кэше.
    std::size_t size() const {
        std::shared_lock lock(mutex_);
        return cache_map_.size();
    }

private:
    std::size_t capacity_;

    // Список хранит пары {ключ, CacheEntry} от MRU (голова) до LRU (хвост)
    std::list<std::pair<std::string, CacheEntry>> cache_list_;

    // Хэш-таблица: ключ → итератор на узел списка, O(1) поиск
    std::unordered_map<std::string, decltype(cache_list_.begin())> cache_map_;

    // shared_mutex: позволяет нескольким потокам читать одновременно
    mutable std::shared_mutex mutex_;
};