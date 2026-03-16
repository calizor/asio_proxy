#pragma once

#include <list>
#include <unordered_map>
#include <mutex>
#include <string>
#include <optional> // Для std::optional (C++17)
#include <cstddef>


class LRUCache {
public:
    // Конструктор принимает максимальное количество элементов в кэше
    explicit LRUCache(size_t capacity) : capacity_(capacity) {}

    // Добавление или обновление элемента в кэше
    void put(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lock(mutex_); // Блокируем для потокобезопасности
        
        auto it = cache_map_.find(key);
        if (it != cache_map_.end()) {
            // Если ключ уже есть, обновляем значение
            it->second->second = value;
            // И переносим узел в начало списка (делаем самым "свежим")
            cache_list_.splice(cache_list_.begin(), cache_list_, it->second);
            return;
        }

        // Если кэш переполнен, удаляем наименее используемый элемент (с конца списка)
        if (cache_list_.size() >= capacity_) {
            auto last = cache_list_.back();
            cache_map_.erase(last.first);
            cache_list_.pop_back();
        }

        // Вставляем новый элемент в начало списка
        cache_list_.emplace_front(key, value);
        // Сохраняем итератор в мапу
        cache_map_[key] = cache_list_.begin();
    }

    // Получение элемента из кэша
    std::optional<std::string> get(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = cache_map_.find(key);
        if (it == cache_map_.end()) {
            return std::nullopt; // Ключ не найден (Cache Miss)
        }
        
        // Ключ найден (Cache Hit). 
        // Переносим элемент в начало списка, так как мы только что к нему обратились
        cache_list_.splice(cache_list_.begin(), cache_list_, it->second);
        
        return it->second->second;
    }

private:
    size_t capacity_;
    
    // Список хранит пары: {URL, HTTP-ответ}
    std::list<std::pair<std::string, std::string>> cache_list_;
    
    // Мапа хранит: URL -> итератор на узел списка
    std::unordered_map<std::string, decltype(cache_list_.begin())> cache_map_;
    
    std::mutex mutex_;
};