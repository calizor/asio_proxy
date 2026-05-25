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
//  DomainConfig — loads MITM / tunnel domain lists from a text config file.
//
//  File format (proxy.conf):
//
//      # comment
//      [tunnel]
//      paypal.com          # this domain and all its subdomains → blind tunnel
//      ocsp.digicert.com
//
//      [mitm]
//      github.com          # explicitly force MITM (optional, useful for testing)
//
//  Rules:
//   - [tunnel] entries are checked first and have higher priority than [mitm].
//   - A domain matches an entry if it equals the entry OR is a subdomain of it.
//     e.g. "cdn.example.com" matches entry "example.com".
//   - Domains not matched by any entry default to MITM.
//   - If the config file is missing, built-in safe defaults are used.
//   - Blank lines and lines starting with '#' are ignored.
//   - Inline comments (everything after the first '#' on a line) are stripped.
// ─────────────────────────────────────────────────────────────────────────────
class DomainConfig {
   public:
    // Load from file. Returns a ready-to-use instance.
    // If the file cannot be opened the built-in defaults are used and a
    // warning is printed; the program continues normally.
    static std::shared_ptr<DomainConfig> load(const std::string& path = "proxy.conf") {
        auto cfg = std::make_shared<DomainConfig>();
        cfg->load_defaults();

        std::ifstream file(path);
        if (!file.is_open()) {
            std::cerr << "[CONFIG] Cannot open \"" << path
                      << "\" — using built-in defaults.\n";
            return cfg;
        }

        // Clear defaults — the file takes full control.
        cfg->tunnel_list_.clear();
        cfg->mitm_list_.clear();

        enum class Section { None, Tunnel, Mitm } section = Section::None;
        std::string line;
        int line_no = 0;

        while (std::getline(file, line)) {
            ++line_no;

            // Strip inline comment.
            if (auto pos = line.find('#'); pos != std::string::npos)
                line.resize(pos);

            // Trim whitespace.
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);

            if (line.empty()) continue;

            // Section header.
            if (line.front() == '[') {
                if (line == "[tunnel]")      section = Section::Tunnel;
                else if (line == "[mitm]")   section = Section::Mitm;
                else {
                    std::cerr << "[CONFIG] Unknown section \"" << line
                              << "\" at line " << line_no << " — skipped.\n";
                    section = Section::None;
                }
                continue;
            }

            // Domain entry.
            switch (section) {
                case Section::Tunnel: cfg->tunnel_list_.push_back(line); break;
                case Section::Mitm:   cfg->mitm_list_.push_back(line);   break;
                case Section::None:
                    std::cerr << "[CONFIG] Entry \"" << line << "\" at line "
                              << line_no << " is outside any section — skipped.\n";
                    break;
            }
        }

        std::cout << "[CONFIG] Loaded from \"" << path << "\": "
                  << cfg->tunnel_list_.size() << " tunnel, "
                  << cfg->mitm_list_.size()   << " mitm entries.\n";
        return cfg;
    }

    // Returns true  → MitmSession
    // Returns false → TunnelSession
    bool is_mitm(const std::string& domain) const {
        // tunnel_list has priority.
        if (matches_any(domain, tunnel_list_)) return false;
        // explicit mitm_list overrides the default (useful for testing).
        if (!mitm_list_.empty() && !matches_any(domain, mitm_list_)) return false;
        return true;
    }

   private:
    std::vector<std::string> tunnel_list_;
    std::vector<std::string> mitm_list_;   // if non-empty: only these → MITM

    // ── Built-in defaults ─────────────────────────────────────────────────────
    // Used when proxy.conf is absent. Covers the most common cases where MITM
    // breaks connections (OCSP, pinned certs, financial apps, messengers).
    void load_defaults() {
        tunnel_list_ = {
            // OCSP / CRL — certificate revocation infrastructure
            "ocsp.digicert.com",
            "ocsp.pki.goog",
            "ocsp.comodoca.com",
            "ocsp.usertrust.com",
            "ocsp.sectigo.com",
            "crl.microsoft.com",
            "crl3.digicert.com",
            "crl4.digicert.com",
            // OS / browser updates
            "update.googleapis.com",
            "clients2.google.com",
            "dl.google.com",
            "update.microsoft.com",
            "windowsupdate.microsoft.com",
            "download.windowsupdate.com",
            // Financial services
            "paypal.com",
            "braintreegateway.com",
            "stripe.com",
            "visa.com",
            "mastercard.com",
            // Secure messaging
            "whatsapp.com",
            "whatsapp.net",
            "signal.org",
            "telegram.org",
            // Apple
            "apple.com",
            "icloud.com",
            "mzstatic.com",
        };
        // mitm_list_ stays empty → all non-tunnelled domains go to MITM
    }

    // ── Suffix matching ───────────────────────────────────────────────────────
    static bool matches_suffix(const std::string& domain, std::string_view suffix) {
        if (domain == suffix) return true;
        if (domain.size() > suffix.size() &&
            domain[domain.size() - suffix.size() - 1] == '.' &&
            domain.compare(domain.size() - suffix.size(), suffix.size(), suffix) == 0)
            return true;
        return false;
    }

    static bool matches_any(const std::string& domain,
                             const std::vector<std::string>& list) {
        for (const auto& s : list)
            if (matches_suffix(domain, s)) return true;
        return false;
    }
};
