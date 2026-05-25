#pragma once

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <boost/asio/ssl.hpp>

#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>

// ─────────────────────────────────────────────────────────────────────────────
//  RAII-обёртки для C-объектов OpenSSL.
//
//  Каждый делитер — stateless-функтор, хранится в типе unique_ptr,
//  поэтому накладных расходов по сравнению с прямым вызовом free-функции нет.
// ─────────────────────────────────────────────────────────────────────────────
namespace ssl_detail {

struct X509Deleter       { void operator()(X509*           p) const noexcept { X509_free(p);           } };
struct EVPKeyDeleter     { void operator()(EVP_PKEY*       p) const noexcept { EVP_PKEY_free(p);       } };
struct EVPPkeyCtxDeleter { void operator()(EVP_PKEY_CTX*   p) const noexcept { EVP_PKEY_CTX_free(p);   } };
struct X509ExtDeleter    { void operator()(X509_EXTENSION* p) const noexcept { X509_EXTENSION_free(p); } };
struct FileDeleter       { void operator()(FILE*           p) const noexcept { if (p) std::fclose(p); } };

using UniqueX509       = std::unique_ptr<X509,            X509Deleter>;
using UniqueEVPKey     = std::unique_ptr<EVP_PKEY,        EVPKeyDeleter>;
using UniqueEVPPkeyCtx = std::unique_ptr<EVP_PKEY_CTX,    EVPPkeyCtxDeleter>;
using UniqueX509Ext    = std::unique_ptr<X509_EXTENSION,  X509ExtDeleter>;
using UniqueFile       = std::unique_ptr<FILE,            FileDeleter>;

// Открывает файл и оборачивает в UniqueFile. Бросает исключение при ошибке.
inline UniqueFile open_file(const std::string& path, const char* mode) {
    UniqueFile f(std::fopen(path.c_str(), mode));
    if (!f)
        throw std::runtime_error("Cannot open file: " + path);
    return f;
}

}  // namespace ssl_detail

// ─────────────────────────────────────────────────────────────────────────────
//  CertManager — генерация, кэширование и выдача ssl::context для MITM.
//
//  Двухуровневый кэш:
//    L1 — in-memory map (готовые ssl::context, самый быстрый путь).
//    L2 — файловая система (PEM-файлы в certs/, переживают рестарт).
//
//  Потокобезопасность: глобальный std::mutex + double-checked locking.
//  Все методы статические — у класса нет состояния экземпляра.
//
//  Замечание: текущая реализация держит лок на всё время генерации
//  сертификата, что сериализует первый запрос к каждому домену.
//  Это не критично в типичном использовании (одна генерация ~50мс),
//  но при массовом потоке новых доменов может стать узким местом.
// ─────────────────────────────────────────────────────────────────────────────
class CertManager {
public:
    // Возвращает готовый ssl::context для domain, создавая его при
    // необходимости. nullptr — при неустранимой ошибке (лог уже записан).
    //
    // Реализация намеренно использует один lock_guard, а не «double-checked
    // locking»: оба лока всё равно были бы exclusive на одном и том же
    // std::mutex, так что DCL здесь не давал выигрыша — только лишнюю пару
    // lock/unlock и иллюзию оптимизации.
    //
    // Узкое место: build_and_cache_context (RSA-keygen + подпись X.509)
    // выполняется под локом, то есть первые запросы к разным новым доменам
    // сериализуются. Для прогретого кэша это незаметно. Если станет важно —
    // переходить на shared_mutex + per-domain promise/future.
    static std::shared_ptr<boost::asio::ssl::context>
    get_context_for_domain(const std::string& domain) {
        std::lock_guard lock(s_mutex);
        if (auto it = s_ctx_cache.find(domain); it != s_ctx_cache.end())
            return it->second;
        return build_and_cache_context(domain);
    }

private:
    // Inline static storage (C++17) — не требует отдельного .cpp.
    static inline std::mutex s_mutex;
    static inline std::unordered_map<
        std::string,
        std::shared_ptr<boost::asio::ssl::context>
    > s_ctx_cache;

    static constexpr const char* CERT_DIR = "certs/";
    static constexpr const char* CA_CRT   = "rootCA.crt";
    static constexpr const char* CA_KEY   = "rootCA.key";

    // ── Сборка ssl::context для одного домена ────────────────────────────────
    static std::shared_ptr<boost::asio::ssl::context>
    build_and_cache_context(const std::string& domain) {
        namespace ssl = boost::asio::ssl;

        std::filesystem::create_directories(CERT_DIR);

        const std::string cert_path = std::string(CERT_DIR) + domain + ".crt";
        const std::string key_path  = std::string(CERT_DIR) + domain + ".key";

        // Если для домена ещё нет PEM-файлов — генерируем сертификат и ключ.
        if (!std::filesystem::exists(cert_path) || !std::filesystem::exists(key_path)) {
            std::cout << "[CertManager] Генерируем сертификат для: " << domain << "\n";
            if (!generate_x509(domain, cert_path, key_path, CA_CRT, CA_KEY)) {
                std::cerr << "[CertManager] Не удалось сгенерировать сертификат для: " << domain << "\n";
                return nullptr;
            }
        }

        // Создаём ssl::context и подгружаем в него цепочку и приватный ключ.
        auto ctx = std::make_shared<ssl::context>(ssl::context::tls_server);
        ctx->set_options(
            ssl::context::default_workarounds |
            ssl::context::no_sslv2            |
            ssl::context::no_sslv3
        );

        try {
            ctx->use_certificate_chain_file(cert_path);
            ctx->use_private_key_file(key_path, ssl::context::pem);
        } catch (const std::exception& e) {
            std::cerr << "[CertManager] Не удалось загрузить cert/key для " << domain
                      << ": " << e.what() << "\n";
            return nullptr;
        }

        s_ctx_cache[domain] = ctx;
        return ctx;
    }

    // ── Генерация X.509-сертификата ──────────────────────────────────────────
    // Шаги: загрузить корневой CA, сгенерировать RSA-ключ, собрать
    // X.509 v3-сертификат с SAN, подписать CA-ключом, сохранить в PEM.
    static bool generate_x509(
        const std::string& domain,
        const std::string& cert_path,
        const std::string& key_path,
        const std::string& ca_cert_path,
        const std::string& ca_key_path)
    {
        using namespace ssl_detail;

        // 1. Загружаем корневой CA-сертификат и его приватный ключ.
        UniqueFile ca_crt_file, ca_key_file;
        try {
            ca_crt_file = open_file(ca_cert_path, "r");
            ca_key_file = open_file(ca_key_path,  "r");
        } catch (const std::exception& e) {
            std::cerr << "[CertManager] " << e.what() << "\n";
            return false;
        }

        UniqueX509   ca_cert(PEM_read_X509      (ca_crt_file.get(), nullptr, nullptr, nullptr));
        UniqueEVPKey ca_pkey(PEM_read_PrivateKey(ca_key_file.get(), nullptr, nullptr, nullptr));

        if (!ca_cert || !ca_pkey) {
            std::cerr << "[CertManager] Не удалось разобрать CA-файлы.\n";
            return false;
        }

        // 2. Генерируем новый RSA-2048 ключ для домена.
        UniqueEVPKey pkey = generate_rsa_key(2048);
        if (!pkey) return false;

        // 3. Собираем X.509 v3-сертификат и подписываем его CA-ключом.
        UniqueX509 cert = build_certificate(domain, pkey.get(), ca_cert.get(), ca_pkey.get());
        if (!cert) return false;

        // 4. Сохраняем в PEM-файлы.
        return write_pem_files(cert.get(), pkey.get(), cert_path, key_path);
    }

    // ── Генерация RSA-ключа ──────────────────────────────────────────────────
    static ssl_detail::UniqueEVPKey generate_rsa_key(int bits) {
        using namespace ssl_detail;

        UniqueEVPPkeyCtx pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
        if (!pctx                                                ||
            EVP_PKEY_keygen_init(pctx.get())               <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(pctx.get(), bits) <= 0)
        {
            std::cerr << "[CertManager] Настройка EVP_PKEY-контекста не удалась.\n";
            return nullptr;
        }

        EVP_PKEY* raw = nullptr;
        if (EVP_PKEY_keygen(pctx.get(), &raw) <= 0 || !raw) {
            std::cerr << "[CertManager] Генерация RSA-ключа не удалась.\n";
            return nullptr;
        }
        return UniqueEVPKey(raw);
    }

    // ── Сборка X.509-сертификата для домена ──────────────────────────────────
    static ssl_detail::UniqueX509 build_certificate(
        const std::string& domain,
        EVP_PKEY*          pkey,
        X509*              ca_cert,
        EVP_PKEY*          ca_pkey)
    {
        using namespace ssl_detail;

        UniqueX509 cert(X509_new());
        if (!cert) return nullptr;

        // Версия X.509 v3 (числовое значение 2), серийник 1, окно валидности.
        // ВНИМАНИЕ: серийный номер фиксированный (=1) — все генерируемые
        // сертификаты будут иметь один и тот же serial. По RFC 5280 это
        // нарушение для CA. Браузеры могут это терпеть, но строгие
        // (Chrome >= 124) — могут начать отвергать.
        X509_set_version(cert.get(), 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
        X509_gmtime_adj(X509_get_notBefore(cert.get()), -10000);    // back-date на случай рассинхронизации часов
        X509_gmtime_adj(X509_get_notAfter(cert.get()),  31536000L); // срок 1 год

        X509_set_pubkey(cert.get(), pkey);

        // Subject Name: Country + Common Name.
        X509_NAME* name = X509_get_subject_name(cert.get());
        X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>("RU"), -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(domain.c_str()), -1, -1, 0);

        // Issuer = subject CA-сертификата (по нему клиент строит цепочку).
        X509_set_issuer_name(cert.get(), X509_get_subject_name(ca_cert));

        // Расширение SAN: покрывает домен и все его поддомены.
        if (!add_san_extension(cert.get(), ca_cert, domain))
            return nullptr;

        // Подпись CA-ключом по SHA-256.
        if (!X509_sign(cert.get(), ca_pkey, EVP_sha256())) {
            std::cerr << "[CertManager] X509_sign failed.\n";
            return nullptr;
        }

        return cert;
    }

    // ── Subject Alternative Name (DNS) ───────────────────────────────────────
    // Добавляет в сертификат расширение SAN с парой записей: сам домен и
    // wildcard-поддомен. Современные браузеры требуют SAN, CN уже не учитывают.
    static bool add_san_extension(X509* cert, X509* ca_cert, const std::string& domain) {
        using namespace ssl_detail;

        X509V3_CTX v3ctx;
        X509V3_set_ctx(&v3ctx, ca_cert, cert, nullptr, nullptr, 0);

        const std::string san_value = "DNS:" + domain + ", DNS:*." + domain;

        UniqueX509Ext ext(X509V3_EXT_conf_nid(
            nullptr, &v3ctx, NID_subject_alt_name, san_value.c_str()));

        if (!ext) {
            std::cerr << "[CertManager] Не удалось создать SAN для: " << domain << "\n";
            return false;
        }

        X509_add_ext(cert, ext.get(), -1);
        return true;
    }

    // ── Запись PEM-файлов сертификата и ключа ────────────────────────────────
    static bool write_pem_files(
        X509*              cert,
        EVP_PKEY*          pkey,
        const std::string& cert_path,
        const std::string& key_path)
    {
        using namespace ssl_detail;

        try {
            UniqueFile cert_file = open_file(cert_path, "wb");
            UniqueFile key_file  = open_file(key_path,  "wb");

            if (!PEM_write_X509(cert_file.get(), cert)) {
                std::cerr << "[CertManager] PEM_write_X509 failed.\n";
                return false;
            }
            if (!PEM_write_PrivateKey(key_file.get(), pkey,
                                      nullptr, nullptr, 0, nullptr, nullptr)) {
                std::cerr << "[CertManager] PEM_write_PrivateKey failed.\n";
                return false;
            }
        } catch (const std::exception& e) {
            std::cerr << "[CertManager] " << e.what() << "\n";
            return false;
        }

        return true;
    }
};