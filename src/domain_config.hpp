#pragma once

#include <algorithm>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
//  DomainConfig — загружает списки MITM- и tunnel-доменов из текстового
//  конфига и решает, как обрабатывать каждый домен.
//
//  Формат файла (proxy.conf):
//
//      # комментарий
//      [tunnel]
//      paypal.com          # сам домен и все поддомены → blind tunnel
//      ocsp.digicert.com
//
//      [mitm]
//      github.com          # явно форсим MITM (опционально, для тестов)
//
//  Правила:
//   - Сначала проверяется [tunnel] — у него приоритет над [mitm].
//   - Домен совпадает с записью, если равен ей ИЛИ является её поддоменом.
//     Пример: "cdn.example.com" совпадает с записью "example.com".
//   - Если домен не попал ни в один список — по умолчанию идёт в MITM.
//   - Если конфиг не найден — используются встроенные дефолты.
//   - Пустые строки и строки с '#' в начале игнорируются.
//   - Inline-комментарии (всё после первого '#') обрезаются.
// ─────────────────────────────────────────────────────────────────────────────
class DomainConfig {
   public:
    // Загрузить конфиг из файла. Если файл недоступен — печатает предупреждение
    // и возвращает экземпляр с встроенными дефолтами (программа продолжает
    // работать).
    static std::shared_ptr<DomainConfig> load(const std::string& path = "proxy.conf") {
        auto cfg = std::make_shared<DomainConfig>();
        cfg->load_defaults();

        std::ifstream file(path);
        if (!file.is_open()) {
            std::cerr << "[CONFIG] Не удалось открыть \"" << path
                      << "\" — используются встроенные дефолты.\n";
            return cfg;
        }

        // Файл найден — он берёт управление на себя, дефолты сбрасываем.
        cfg->tunnel_list_.clear();
        cfg->mitm_list_.clear();

        enum class Section { None, Tunnel, Mitm } section = Section::None;
        std::string line;
        int         line_no = 0;

        while (std::getline(file, line)) {
            ++line_no;

            // Обрезаем inline-комментарий.
            if (auto pos = line.find('#'); pos != std::string::npos)
                line.resize(pos);

            // Триммируем пробельные символы по краям.
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);

            if (line.empty()) continue;

            // Заголовок секции.
            if (line.front() == '[') {
                if      (line == "[tunnel]") section = Section::Tunnel;
                else if (line == "[mitm]")   section = Section::Mitm;
                else {
                    std::cerr << "[CONFIG] Неизвестная секция \"" << line
                              << "\" в строке " << line_no << " — пропущена.\n";
                    section = Section::None;
                }
                continue;
            }

            // Запись домена.
            switch (section) {
                case Section::Tunnel: cfg->tunnel_list_.push_back(line); break;
                case Section::Mitm:   cfg->mitm_list_.push_back(line);   break;
                case Section::None:
                    std::cerr << "[CONFIG] Запись \"" << line << "\" в строке "
                              << line_no << " вне какой-либо секции — пропущена.\n";
                    break;
            }
        }

        std::cout << "[CONFIG] Загружено из \"" << path << "\": "
                  << cfg->tunnel_list_.size() << " tunnel, "
                  << cfg->mitm_list_.size()   << " mitm.\n";
        return cfg;
    }

    // Возвращает true  → нужна MitmSession (расшифровываем TLS).
    // Возвращает false → нужна TunnelSession (просто прокидываем байты).
    bool is_mitm(const std::string& domain) const {
        // У tunnel_list_ приоритет.
        if (matches_any(domain, tunnel_list_)) return false;
        // Если задан явный белый список mitm_list_ — берём в MITM только то,
        // что в нём есть. Иначе по умолчанию всё, что не tunnel, идёт в MITM.
        if (!mitm_list_.empty() && !matches_any(domain, mitm_list_)) return false;
        return true;
    }

   private:
    std::vector<std::string> tunnel_list_;
    std::vector<std::string> mitm_list_;  // если непустой — MITM только для них

    // ── Встроенные дефолты ───────────────────────────────────────────────────
    // Используются, если proxy.conf отсутствует. Покрывают типичные случаи,
    // где MITM ломает соединение: OCSP, pinned-сертификаты, банкинг,
    // мессенджеры с end-to-end шифрованием.
    void load_defaults() {
        tunnel_list_ = {
            // OCSP / CRL — инфраструктура отзыва сертификатов
            "ocsp.digicert.com",
            "ocsp.pki.goog",
            "ocsp.comodoca.com",
            "ocsp.usertrust.com",
            "ocsp.sectigo.com",
            "crl.microsoft.com",
            "crl3.digicert.com",
            "crl4.digicert.com",
            // Обновления ОС и браузеров
            "update.googleapis.com",
            "clients2.google.com",
            "dl.google.com",
            "update.microsoft.com",
            "windowsupdate.microsoft.com",
            "download.windowsupdate.com",
            // Финансовые сервисы
            "paypal.com",
            "braintreegateway.com",
            "stripe.com",
            "visa.com",
            "mastercard.com",
            // Защищённые мессенджеры
            "whatsapp.com",
            "whatsapp.net",
            "signal.org",
            "telegram.org",
            // Apple
            "apple.com",
            "icloud.com",
            "mzstatic.com",
        };
        // mitm_list_ остаётся пустым → всё, что не tunnel, идёт в MITM
    }

    // ── Сопоставление по суффиксу ────────────────────────────────────────────
    // Домен совпадает либо ровно, либо как поддомен (через '.').
    // "cdn.example.com" совпадает с "example.com",
    // но "notexample.com" — не совпадает.
    static bool matches_suffix(const std::string& domain, std::string_view suffix) {
        if (domain == suffix) return true;
        if (domain.size() > suffix.size() &&
            domain[domain.size() - suffix.size() - 1] == '.' &&
            domain.compare(domain.size() - suffix.size(), suffix.size(), suffix) == 0)
            return true;
        return false;
    }

    static bool matches_any(const std::string&              domain,
                            const std::vector<std::string>& list) {
        for (const auto& s : list)
            if (matches_suffix(domain, s)) return true;
        return false;
    }
};
