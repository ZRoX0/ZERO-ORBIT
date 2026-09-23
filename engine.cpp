// engine.cpp — ZERO-ORBIT high-performance header / technology analyzer.
//
// Protocol:
//   stdin  : {"headers": {...}, "body": "..."}
//   stdout : {"technologies": [...], "signals": [...], "score": N}

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cctype>
#include <cstdio>

// ---------- Minimal JSON-ish helpers (no external deps) ----------

static std::string read_all_stdin() {
    std::ostringstream ss;
    ss << std::cin.rdbuf();
    return ss.str();
}

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return s;
}

// Very small JSON string extractor: finds "key":"value" or "key": { ... } first level.
// This is intentionally tiny — for production use a real parser.
static std::string extract_string(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    auto p = json.find(needle);
    if (p == std::string::npos) return "";
    p = json.find(':', p + needle.size());
    if (p == std::string::npos) return "";
    ++p;
    while (p < json.size() && std::isspace((unsigned char)json[p])) ++p;
    if (p >= json.size() || json[p] != '"') return "";
    ++p;
    std::string out;
    while (p < json.size() && json[p] != '"') {
        if (json[p] == '\\' && p + 1 < json.size()) { ++p; }
        out.push_back(json[p++]);
    }
    return out;
}

static std::map<std::string, std::string> extract_headers(const std::string& json) {
    std::map<std::string, std::string> hdrs;
    auto p = json.find("\"headers\"");
    if (p == std::string::npos) return hdrs;
    p = json.find('{', p);
    if (p == std::string::npos) return hdrs;
    int depth = 1; auto q = p + 1;
    std::string body;
    while (q < json.size() && depth > 0) {
        if (json[q] == '{') depth++;
        else if (json[q] == '}') { depth--; if (depth == 0) break; }
        body.push_back(json[q++]);
    }
    // parse simple "k":"v" pairs
    size_t i = 0;
    while (i < body.size()) {
        auto k1 = body.find('"', i);
        if (k1 == std::string::npos) break;
        auto k2 = body.find('"', k1 + 1);
        if (k2 == std::string::npos) break;
        std::string k = body.substr(k1 + 1, k2 - k1 - 1);
        auto colon = body.find(':', k2);
        if (colon == std::string::npos) break;
        auto v1 = body.find('"', colon);
        if (v1 == std::string::npos) break;
        auto v2 = body.find('"', v1 + 1);
        if (v2 == std::string::npos) break;
        std::string v = body.substr(v1 + 1, v2 - v1 - 1);
        hdrs[k] = v;
        i = v2 + 1;
    }
    return hdrs;
}

// ---------- Fingerprinting rules ----------

struct TechRule {
    std::string name;
    std::string header;   // header name (lowercase) to inspect; "" = any
    std::string needle;   // lowercase substring to look for
};

static std::vector<TechRule> RULES = {
    {"Nginx",        "server",         "nginx"},
    {"Apache",       "server",         "apache"},
    {"IIS",          "server",         "microsoft-iis"},
    {"Cloudflare",   "server",         "cloudflare"},
    {"OpenResty",    "server",         "openresty"},
    {"LiteSpeed",    "server",         "litespeed"},
    {"Express",      "x-powered-by",   "express"},
    {"PHP",          "x-powered-by",   "php"},
    {"ASP.NET",      "x-powered-by",   "asp.net"},
    {"Next.js",      "x-powered-by",   "next.js"},
    {"Ruby on Rails","x-powered-by",   "phusion"},
    {"Java/Servlet", "x-powered-by",   "servlet"},
    {"WordPress",    "",               "wp-content"},
    {"WordPress",    "",               "wp-includes"},
    {"Drupal",       "",               "drupal"},
    {"Joomla",       "",               "joomla"},
    {"React",        "",               "data-reactroot"},
    {"Vue",          "",               "__vue__"},
    {"Angular",      "",               "ng-version"},
    {"jQuery",       "",               "jquery"},
    {"Bootstrap",    "",               "bootstrap.min.css"},
    {"Cloudflare CDN","cf-ray",        ""},
    {"HSTS enabled", "strict-transport-security",""},
    {"CSP enabled",  "content-security-policy",  ""},
};

// ---------- Detection ----------

struct Signal {
    std::string kind;
    std::string detail;
    int severity; // 1..5
};

static void emit_json(const std::vector<std::string>& techs,
                     const std::vector<Signal>& signals,
                     int score) {
    std::cout << "{";
    std::cout << "\"technologies\":[";
    for (size_t i = 0; i < techs.size(); ++i) {
        if (i) std::cout << ",";
        std::cout << "\"" << techs[i] << "\"";
    }
    std::cout << "],\"signals\":[";
    for (size_t i = 0; i < signals.size(); ++i) {
        if (i) std::cout << ",";
        std::cout << "{\"kind\":\"" << signals[i].kind
                  << "\",\"detail\":\"" << signals[i].detail
                  << "\",\"severity\":" << signals[i].severity << "}";
    }
    std::cout << "],\"score\":" << score << "}";
    std::cout << std::endl;
}

int main(int argc, char** argv) {
    std::string mode = (argc > 1) ? argv[1] : "analyze";
    std::string input = read_all_stdin();
    if (input.empty()) {
        std::cerr << "engine: empty input\n";
        return 1;
    }

    if (mode != "analyze") {
        std::cerr << "engine: unknown mode\n";
        return 2;
    }

    auto headers = extract_headers(input);
    std::string body = extract_string(input, "body");
    std::string body_l = lower(body);

    std::vector<std::string> techs;
    std::vector<Signal> signals;

    // Header / body rule matching
    for (const auto& r : RULES) {
        bool hit = false;
        if (!r.header.empty()) {
            auto it = headers.find(r.header);
            if (it == headers.end()) {
                // try case-insensitive lookup
                for (auto& kv : headers) {
                    if (lower(kv.first) == r.header) { it = headers.find(kv.first); break; }
                }
            }
            if (it != headers.end()) {
                if (r.needle.empty() && !it->second.empty()) hit = true;
                else if (lower(it->second).find(r.needle) != std::string::npos) hit = true;
            }
        } else if (!r.needle.empty()) {
            if (body_l.find(r.needle) != std::string::npos) hit = true;
        }
        if (hit) {
            if (std::find(techs.begin(), techs.end(), r.name) == techs.end())
                techs.push_back(r.name);
        }
    }

    // Signal scoring
    int score = 0;
    auto lh = [&](const std::string& k)->std::string{
        for (auto& kv : headers) if (lower(kv.first) == k) return lower(kv.second);
        return "";
    };
    if (lh("strict-transport-security").empty()) {
        signals.push_back({"headers", "missing HSTS", 3}); score += 2;
    }
    if (lh("content-security-policy").empty()) {
        signals.push_back({"headers", "missing CSP", 3}); score += 2;
    }
    if (lh("x-content-type-options").empty()) {
        signals.push_back({"headers", "missing X-Content-Type-Options", 2}); score += 1;
    }
    if (lh("x-frame-options").empty()) {
        signals.push_back({"headers", "missing X-Frame-Options", 2}); score += 1;
    }
    if (lh("referrer-policy").empty()) {
        signals.push_back({"headers", "missing Referrer-Policy", 2}); score += 1;
    }
    if (lh("server").find("nginx/") != std::string::npos ||
        lh("server").find("apache/") != std::string::npos) {
        signals.push_back({"info", "server version disclosed", 1}); score += 1;
    }

    // Normalize score 0..5
    if (score > 5) score = 5;

    emit_json(techs, signals, score);
    return 0;
}