#pragma once

#include <string>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <memory>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <boost/asio/ssl.hpp> // Подключаем SSL из Boost

class CertManager {
    static inline std::mutex cert_mutex_;
    // КЭШ L1: Хранит готовые к работе SSL-контексты прямо в ОЗУ
    static inline std::unordered_map<std::string, std::shared_ptr<boost::asio::ssl::context>> ctx_cache_;

public:
    // Теперь функция возвращает ГОТОВЫЙ КОНТЕКСТ, а не пути к файлам
    static std::shared_ptr<boost::asio::ssl::context> get_context_for_domain(const std::string& domain) {
        
        // --- 1. БЫСТРАЯ ПРОВЕРКА В ОЗУ (Double-Checked Locking, шаг 1) ---
        {
            std::lock_guard<std::mutex> lock(cert_mutex_);
            auto it = ctx_cache_.find(domain);
            if (it != ctx_cache_.end()) {
                return it->second; // МГНОВЕННЫЙ ВОЗВРАТ! Никакого диска.
            }
        }

        // --- 2. БЛОКИРУЕМ ПОТОК ДЛЯ РАБОТЫ С ДИСКОМ ---
        std::lock_guard<std::mutex> lock(cert_mutex_);

        // ПОВТОРНАЯ ПРОВЕРКА (вдруг другой поток уже создал контекст, пока мы ждали мьютекс)
        if (ctx_cache_.find(domain) != ctx_cache_.end()) {
            return ctx_cache_[domain];
        }

        std::string cert_dir = "certs/";
        if (!std::filesystem::exists(cert_dir)) {
            std::filesystem::create_directory(cert_dir);
        }

        std::string out_crt = cert_dir + domain + ".crt";
        std::string out_key = cert_dir + domain + ".key";

        // --- 3. ГЕНЕРАЦИЯ, ЕСЛИ НЕТ НА ДИСКЕ ---
        if (!std::filesystem::exists(out_crt) || !std::filesystem::exists(out_key)) {
            std::cout << "[CERT] Generating new certificate for: " << domain << "...\n";
            if (!generate_x509(domain, out_crt, out_key, "rootCA.crt", "rootCA.key")) {
                std::cerr << "[CERT] Critical error: failed to generate X509!\n";
                return nullptr;
            }
        }

        // --- 4. СОБИРАЕМ КОНТЕКСТ И СОХРАНЯЕМ В ОЗУ ---
        auto ctx = std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tls_server);
        ctx->set_options(boost::asio::ssl::context::default_workarounds |
                         boost::asio::ssl::context::no_sslv2 |
                         boost::asio::ssl::context::no_sslv3);
        
        try {
            ctx->use_certificate_chain_file(out_crt);
            ctx->use_private_key_file(out_key, boost::asio::ssl::context::pem);
        } catch (const std::exception& e) {
            std::cerr << "[CERT] Failed to load certs into context: " << e.what() << "\n";
            return nullptr;
        }

        // Кладём в оперативную память для будущих запросов
        ctx_cache_[domain] = ctx;
        
        return ctx;
    }

private:
    static bool generate_x509(const std::string& domain, const std::string& cert_path, const std::string& key_path, 
                              const std::string& ca_cert_path, const std::string& ca_key_path) {
        
        // --- 1. Читаем Корневой Сертификат (CA) и Ключ ---
        FILE* ca_crt_file = fopen(ca_cert_path.c_str(), "r");
        FILE* ca_key_file = fopen(ca_key_path.c_str(), "r");
        if (!ca_crt_file || !ca_key_file) {
            std::cerr << "Cannot open root CA files!\n";
            return false;
        }

        X509* ca_cert = PEM_read_X509(ca_crt_file, nullptr, nullptr, nullptr);
        EVP_PKEY* ca_pkey = PEM_read_PrivateKey(ca_key_file, nullptr, nullptr, nullptr);
        fclose(ca_crt_file);
        fclose(ca_key_file);

        if (!ca_cert || !ca_pkey) return false;

        // --- 2. Генерируем новый приватный ключ для домена (RSA 2048) ---
        EVP_PKEY* pkey = EVP_PKEY_new();
        RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        EVP_PKEY_assign_RSA(pkey, rsa);

        // --- 3. Создаем новый сертификат ---
        X509* x509 = X509_new();
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1); // Серийный номер
        X509_gmtime_adj(X509_get_notBefore(x509), 0);     // Действителен с текущего момента
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // Действителен 1 год (в секундах)
        X509_set_pubkey(x509, pkey);

        // --- 4. Задаем Имя субъекта (Common Name) ---
        X509_NAME* name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"RU", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)domain.c_str(), -1, -1, 0);

        // Устанавливаем издателя (наш CA)
        X509_set_issuer_name(x509, X509_get_subject_name(ca_cert));

        // --- 5. Добавляем расширение SAN (Subject Alternative Name) ---
        X509V3_CTX ctx;
        X509V3_set_ctx(&ctx, ca_cert, x509, nullptr, nullptr, 0);
        std::string san_str = "DNS:" + domain + ", DNS:*." + domain;
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, san_str.c_str());
        if (ext) {
            X509_add_ext(x509, ext, -1);
            X509_EXTENSION_free(ext);
        }

        // --- 6. Подписываем сертификат корневым ключом CA ---
        X509_sign(x509, ca_pkey, EVP_sha256());

        // --- 7. Сохраняем сгенерированные сертификат и ключ на диск ---
        FILE* out_crt_file = fopen(cert_path.c_str(), "wb");
        FILE* out_key_file = fopen(key_path.c_str(), "wb");
        
        bool success = false;
        if (out_crt_file && out_key_file) {
            PEM_write_X509(out_crt_file, x509);
            PEM_write_PrivateKey(out_key_file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
            success = true;
        }

        if (out_crt_file) fclose(out_crt_file);
        if (out_key_file) fclose(out_key_file);

        // --- 8. Освобождаем память (Стиль C) ---
        X509_free(x509);
        EVP_PKEY_free(pkey);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_pkey);

        return success;
    }
};