// ============================================================
//  KeyGate.h  -  one-time-use license key check against a
//                 GitHub repo file (keys.txt, one key per line)
//
//  How it works:
//   1. On startup, GET the keys file from your GitHub repo via
//      the Contents API.
//   2. Ask the user for a key.
//   3. If the key is in the file -> remove it and PUT the
//      updated file back (commit), so it can never be reused.
//   4. If not found -> deny.
//
//  SECURITY NOTE: the GitHub token below ships inside the .exe
//  and can be extracted with `strings` or a disassembler by
//  anyone who has the binary. Scope it to a FINE-GRAINED PAT
//  with access to ONLY this one repo, permission "Contents:
//  Read and write", nothing else. Keep the repo private. Rotate
//  the token occasionally. For stronger security, replace this
//  with a tiny serverless proxy later so the token never ships
//  client-side at all.
// ============================================================
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#pragma comment(lib, "winhttp.lib")

// ============================================================
//  CONFIG - EDIT THESE BEFORE BUILDING
// ============================================================
namespace KeyGateConfig {
    static const std::wstring HOST      = L"api.github.com";
    static const std::string  OWNER     = "";   // e.g. "tasfik-abdullah"
    static const std::string  REPO      = "";          // e.g. "scanner-keys"
    static const std::string  FILE_PATH = "keys.txt";               // one key per line
    static const std::string  BRANCH    = "main";
    // Fine-grained PAT, scoped ONLY to the repo above, Contents: Read & write.
    static const std::string  TOKEN     = "";
}

// ---------- base64 ----------
namespace kg_b64 {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    inline std::string encode(const std::string& in) {
        std::string out;
        int val = 0, bits = -6;
        for (unsigned char c : in) {
            val = (val << 8) + c;
            bits += 8;
            while (bits >= 0) {
                out.push_back(tbl[(val >> bits) & 0x3F]);
                bits -= 6;
            }
        }
        if (bits > -6) out.push_back(tbl[((val << 8) >> (bits + 8)) & 0x3F]);
        while (out.size() % 4) out.push_back('=');
        return out;
    }

    inline std::string decode(const std::string& in) {
        static std::vector<int> T;
        if (T.empty()) {
            T.assign(256, -1);
            for (int i = 0; i < 64; i++) T[(unsigned char)tbl[i]] = i;
        }
        std::string out;
        int val = 0, bits = -8;
        for (unsigned char c : in) {
            if (T[c] == -1) continue; // skip '=', newlines, anything non-base64
            val = (val << 6) + T[c];
            bits += 6;
            if (bits >= 0) {
                out.push_back(char((val >> bits) & 0xFF));
                bits -= 8;
            }
        }
        return out;
    }
}

// ---------- minimal JSON string-field extraction (no full parser needed) ----------
namespace kg_json {
    inline std::string extractRaw(const std::string& json, const std::string& field) {
        std::string key = "\"" + field + "\":\"";
        size_t pos = json.find(key);
        if (pos == std::string::npos) return "";
        pos += key.size();
        std::string out;
        while (pos < json.size()) {
            char c = json[pos];
            if (c == '\\' && pos + 1 < json.size()) { out += c; out += json[pos + 1]; pos += 2; continue; }
            if (c == '"') break;
            out += c; pos++;
        }
        return out;
    }
    inline std::string unescape(const std::string& s) {
        std::string out; out.reserve(s.size());
        for (size_t i = 0; i < s.size(); i++) {
            if (s[i] == '\\' && i + 1 < s.size()) {
                char n = s[i + 1];
                if (n == 'n' || n == 'r') { i++; continue; }     // drop, base64 ignores whitespace anyway
                if (n == '/')  { out += '/';  i++; continue; }
                if (n == '\\') { out += '\\'; i++; continue; }
                if (n == '"')  { out += '"';  i++; continue; }
                out += s[i];
            } else out += s[i];
        }
        return out;
    }
    inline std::string field(const std::string& json, const std::string& f) {
        return unescape(extractRaw(json, f));
    }
    inline std::string escape(const std::string& s) {
        std::string out;
        for (char c : s) {
            if (c == '"' || c == '\\') { out += '\\'; out += c; }
            else if (c == '\n') out += "\\n";
            else out += c;
        }
        return out;
    }
}

// ---------- WinHTTP request ----------
struct KgHttpResult {
    bool ok = false;
    int  status = 0;
    std::string body;
};

inline KgHttpResult KgHttpsRequest(const std::wstring& verb, const std::string& path,
                                    const std::vector<std::string>& headerLines,
                                    const std::string& body) {
    KgHttpResult res;
    HINTERNET hSession = WinHttpOpen(L"DragonKeyGate/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return res;

    HINTERNET hConnect = WinHttpConnect(hSession, KeyGateConfig::HOST.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return res; }

    std::wstring wpath(path.begin(), path.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, verb.c_str(), wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return res; }

    for (auto& h : headerLines) {
        std::wstring wh(h.begin(), h.end());
        WinHttpAddRequestHeaders(hRequest, wh.c_str(), (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
    }

    BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(),
        (DWORD)body.size(), (DWORD)body.size(), 0);

    if (!sent) {
        std::cout << "  [DEBUG] WinHttpSendRequest failed, GetLastError=" << GetLastError() << "\n";
    }

    if (sent && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD statusCode = 0, size = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
        res.status = (int)statusCode;

        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
            std::vector<char> buf(avail);
            DWORD read = 0;
            if (WinHttpReadData(hRequest, buf.data(), avail, &read) && read > 0)
                res.body.append(buf.data(), read);
            else break;
        }
        res.ok = true;
    } else if (sent) {
        std::cout << "  [DEBUG] WinHttpReceiveResponse failed, GetLastError=" << GetLastError() << "\n";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return res;
}

inline std::vector<std::string> KgAuthHeaders() {
    return {
        "Authorization: token " + KeyGateConfig::TOKEN,
        "User-Agent: DragonKeyGate",
        "Accept: application/vnd.github+json",
        "X-GitHub-Api-Version: 2022-11-28",
        "Content-Type: application/json"
    };
}

// ---------- fetch + parse keys file ----------
struct KgKeysFile {
    bool ok = false;
    std::string sha;
    std::vector<std::string> keys;
};

inline KgKeysFile KgFetchKeys() {
    KgKeysFile kf;
    std::string path = "/repos/" + KeyGateConfig::OWNER + "/" + KeyGateConfig::REPO +
                        "/contents/" + KeyGateConfig::FILE_PATH + "?ref=" + KeyGateConfig::BRANCH;
    KgHttpResult r = KgHttpsRequest(L"GET", path, KgAuthHeaders(), "");
    if (!r.ok || r.status != 200) {
        std::cout << "  [DEBUG] GitHub GET failed, ok=" << r.ok << " status=" << r.status
                  << " body=" << r.body.substr(0, 200) << "\n";
        return kf;
    }

    kf.sha = kg_json::field(r.body, "sha");
    std::string contentB64 = kg_json::extractRaw(r.body, "content"); // raw, decode() will skip \n chars fine
    std::string raw = kg_b64::decode(contentB64);

    std::string cur;
    for (char c : raw) {
        if (c == '\n' || c == '\r') {
            if (!cur.empty()) { kf.keys.push_back(cur); cur.clear(); }
        } else cur += c;
    }
    if (!cur.empty()) kf.keys.push_back(cur);
    kf.ok = true;
    return kf;
}

inline bool KgPushUpdatedKeys(const KgKeysFile& kf, const std::vector<std::string>& newKeys) {
    std::string joined;
    for (auto& k : newKeys) { joined += k; joined += "\n"; }
    std::string encoded = kg_b64::encode(joined);

    std::string body = "{";
    body += "\"message\":\"" + kg_json::escape(std::string("Consume key via StringScanner")) + "\",";
    body += "\"content\":\"" + encoded + "\",";
    body += "\"sha\":\"" + kf.sha + "\",";
    body += "\"branch\":\"" + KeyGateConfig::BRANCH + "\"";
    body += "}";

    std::string path = "/repos/" + KeyGateConfig::OWNER + "/" + KeyGateConfig::REPO +
                        "/contents/" + KeyGateConfig::FILE_PATH;
    KgHttpResult r = KgHttpsRequest(L"PUT", path, KgAuthHeaders(), body);
    return r.ok && (r.status == 200 || r.status == 201);
}

// ---------- the gate itself: call this once, near the top of main() ----------
inline bool RunKeyGate() {
    std::cout << "\n  Enter your license key: ";
    std::string input;
    std::getline(std::cin, input);
    while (!input.empty() && (input.back() == '\r' || input.back() == '\n' || input.back() == ' '))
        input.pop_back();

    if (input.empty()) {
        std::cout << "  [ERROR] No key entered.\n";
        return false;
    }

    std::cout << "  [*] Verifying key...\n";
    for (int attempt = 0; attempt < 3; attempt++) {
        KgKeysFile kf = KgFetchKeys();
        if (!kf.ok) {
            std::cout << "  [ERROR] Could not reach the key server. Check your internet connection.\n";
            return false;
        }

        auto it = std::find(kf.keys.begin(), kf.keys.end(), input);
        if (it == kf.keys.end()) {
            std::cout << "  [DENIED] Invalid or already-used key.\n";
            return false;
        }

        std::vector<std::string> remaining;
        for (auto& k : kf.keys) if (k != input) remaining.push_back(k);

        if (KgPushUpdatedKeys(kf, remaining)) {
            std::cout << "  [OK] Key accepted and consumed. It cannot be reused.\n";
            return true;
        }
        // Someone else consumed a key at the same moment (sha mismatch) -> retry.
        std::cout << "  [*] Retry (" << (attempt + 1) << "/3)...\n";
        Sleep(400);
    }
    std::cout << "  [ERROR] Could not consume key (possible race with another user). Try again.\n";
    return false;
}
