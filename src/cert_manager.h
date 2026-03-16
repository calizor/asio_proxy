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

class CertManager {
public:
    static bool prepare_cert_for_domain(const std::string& domain, std::string& out_crt, std::string& out_key) {
        std::string cert_dir = "certs/";
        if (!std::filesystem::exists(cert_dir)) {
            std::filesystem::create_directory(cert_dir);
        }

        out_crt = cert_dir + domain + ".crt";
        out_key = cert_dir + domain + ".key";

        if (std::filesystem::exists(out_crt) && std::filesystem::exists(out_key)) {
            return true; // Сертификат уже в кэше файлов
        }

        std::cout << "[CERT] Generating new certificate for: " << domain << " using OpenSSL API...\n";
        return generate_x509(domain, out_crt, out_key, "rootCA.crt", "rootCA.key");
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