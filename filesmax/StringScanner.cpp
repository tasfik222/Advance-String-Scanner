// ============================================================
//  DRAGON STRING SCANNER v2.1  -  FAST EDITION
//  Full drive scan - EXE, DLL, SYS files
//  Detects suspicious strings and writes an HTML report
//  Developer: Tasfik Abdullah
//  Build: g++ -o StringScanner.exe StringScanner.cpp
//         -lshlwapi -lshell32 -ladvapi32 -std=c++17 -O2 -static
//
//  USAGE:
//    StringScanner.exe                 scan the C: drive
//    StringScanner.exe D:\            scan the D: drive
//    StringScanner.exe C:\Games        scan one folder
//    StringScanner.exe --fast          skip C:\Windows (much faster)
//    StringScanner.exe --threads 4     set worker thread count
//
//  WHY v2.1 IS FAST
//   1. Aho-Corasick: ALL keywords (ASCII + UTF-16) are searched in
//      ONE pass over each file. v1.0 re-read the whole file once
//      per keyword (~200 passes, x2 for UTF-16).
//   2. Multi-threaded: one worker per CPU thread.
//   3. Streaming: files are read in 4 MB chunks, no huge buffers.
//   4. Fast folder enumeration, size filter before opening a file,
//      junctions and OneDrive placeholders are skipped.
//   5. (v2.1) PE structure analysis: finds packed / protected files
//      (UPX, VMProtect, Themida ...) even when no strings are visible,
//      shows SHA-256 + VirusTotal link, and checks a known-bad hash
//      list (built in + optional hashes.txt next to the exe).
// ============================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601   // Windows 7+
#endif
#ifndef WINVER
#define WINVER 0x0601
#endif
#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <deque>
#include <map>
#include <set>
#include <algorithm>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <cstdio>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <utility>
#include "KeyGate.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

// ============================================================
//  SUSPICIOUS STRING DATABASE
// ============================================================

// Category: Cheat / Hack keywords
static const std::vector<std::string> CHEAT_STRINGS = {
    // Aimbot
    "aimbot","aim_bot","AimBot","AIMBOT",
    "triggerbot","trigger_bot","TriggerBot",
    "aimware","aimjunkies","aim_fov","aim_smooth",
    "BoneAim","bone_aim","TargetBone","target_bone",
    "AutoAim","auto_aim","SilentAim","silent_aim",
    // ESP / Wallhack
    "wallhack","wall_hack","WallHack","WALLHACK",
    "esp_enable","ESP_ENABLE","DrawESP","draw_esp",
    "BoneESP","SkeletonESP","skeleton_esp",
    "PlayerESP","player_esp","BoxESP","box_esp",
    "NoFog","no_fog","NoRecoil","no_recoil",
    // Speed / Movement
    "speedhack","speed_hack","SpeedHack","SPEEDHACK",
    "NoClip","noclip","no_clip","GodMode","god_mode",
    "FlyHack","fly_hack","BhopHack","bhop_hack",
    // Injector keywords
    "ManualMap","manual_map","DllInjection","dll_injection",
    "LoadLibraryInject","CreateRemoteThread",
    "NtCreateThreadEx","RtlCreateUserThread",
    "LdrLoadDll","LdrpLoadDll",
    "WriteProcessMemory","VirtualAllocEx",
    // Cheat tools
    "CheatEngine","cheat_engine","GameGuardian",
    "game_guardian","GGClient","gg_client",
    "WeAreDevs","wearedevs","Extremeinjector",
    "xenos","X-Bows","GameHacker",
    // Free Fire specific
    "FreeFire","freefire_hack","ff_aimbot","ff_esp",
    "GarenaFF","garena_cheat","FFHack","ff_hack",
    "FreefireAimbot","freefireaimbot",
    // Memory manipulation
    "ReadProcMem","WriteProcMem",
    "GameHook","game_hook","MemoryHack","memory_hack",
    "PatternScan","pattern_scan","SigScan","sig_scan",
    // Anti-detection bypass
    "AntiDetect","anti_detect","BypassAC","bypass_ac",
    "AntiCheatBypass","anticheaat","KillAC","kill_ac",
    "DisableAC","disable_ac","ACBypass",
    // Crypto / Obfuscation suspicious
    "XorDecrypt","xor_decrypt","ObfuscatedCode",
    "UnpackPayload","unpack_payload","Shellcode","shellcode",
    // Suspicious API combinations
    "VirtualProtect","NtProtectVirtualMemory",
    "ZwProtectVirtualMemory","NtWriteVirtualMemory",
    "ZwWriteVirtualMemory","NtReadVirtualMemory",
    "NtAllocateVirtualMemory","ZwAllocateVirtualMemory",
    // Debug / Reverse engineering tools
    "x64dbg","x32dbg","ollydbg","OllyDbg",
    "IDA Pro","idapro","Ghidra","ghidra",
    "ScyllaHide","scyllahide","TitanHide","titanhide",
    // Rootkit indicators
    "HideProcess","hide_process","HideModule","hide_module",
    "KernelHook","kernel_hook","SSDTHook","ssdt_hook",
    "DKOM","DirectKernelObject","InfinityHook",
    // Packer/Crypter
    "UPX!","PECompact","ASPack","Themida",
    "VMProtect","vmp_begin","vmp_end",
    ".enigma","WinLicense","Obsidium",
};

// Category: Suspicious API strings (often in malware/cheats)
static const std::vector<std::string> SUSPICIOUS_API = {
    "OpenProcess","CreateRemoteThread","VirtualAllocEx",
    "WriteProcessMemory","ReadProcessMemory","SetWindowsHookEx",
    "NtQuerySystemInformation","NtQueryInformationProcess",
    "ZwQuerySystemInformation","ZwUnmapViewOfSection",
    "NtUnmapViewOfSection","RtlDecompressBuffer",
    "IsDebuggerPresent","CheckRemoteDebuggerPresent",
    "OutputDebugString","FindWindow","EnumWindows",
    "GetAsyncKeyState","GetKeyState","RegisterHotKey",
    "CreateToolhelp32Snapshot","Module32First","Module32Next",
    "Thread32First","Thread32Next","Process32First","Process32Next",
};

// Category: Known cheat-related URLs / domains
static const std::vector<std::string> SUSPICIOUS_URLS = {
    "aimware.net","cheatautomation.com","unknowncheats.me",
    "mpgh.net","hackforums.net","aimjunkies.com",
    "skycheats.com","iwantcheats.net","wallhax.com",
    "ring-0.xyz","ring0.xyz","gamehacking.org",
    "cheathappens.com","fearless-cheat.pw",
    "gamekiller.net","wearedevs.net","gameoverlay",
    "freefireaimbot","ff-hack","garena-cheat",
    "mobilehack","modhack.net","apkhack",
    "luckyatch","pubghack","bgmihack",
};

// Category: Suspicious registry / file paths
static const std::vector<std::string> SUSPICIOUS_PATHS = {
    "\\temp\\inject","\\temp\\cheat","\\temp\\hack",
    "\\appdata\\cheat","\\appdata\\hack","\\appdata\\inject",
    "%temp%\\","APPDATA\\inject","inject.dll",
    "cheat.dll","hack.dll","esp.dll","aimbot.dll",
    "bypass.dll","loader.dll","trainer.dll",
};


// ============================================================
//  DATA STRUCTURES
// ============================================================
enum Severity { SEV_INFO=0, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL };

static int PointsFor(Severity s) {
    return s == SEV_CRITICAL ? 40 : s == SEV_HIGH ? 20 : s == SEV_MEDIUM ? 10 : s == SEV_LOW ? 5 : 1;
}

struct StringMatch {
    std::string keyword;
    std::string category;
    Severity    severity;
    size_t      offset;      // file offset of first hit
};

struct FileResult {
    std::string              path;   // UTF-8
    std::string              name;
    std::string              ext;
    size_t                   fileSize    = 0;
    int                      score       = 0;
    Severity                 maxSeverity = SEV_INFO;
    std::vector<StringMatch> matches;
    bool                     isSigned    = false;   // embedded certificate present (not validated)
    std::string              sha256;                // only for MEDIUM+ findings
    std::string              peInfo;                // sections / entropy summary
};

// ============================================================
//  GLOBALS
// ============================================================
static std::vector<FileResult> g_Results;
static int g_ScannedFiles    = 0;
static int g_SkippedFiles    = 0;
static int g_SuspiciousFiles = 0;
static int g_TotalMatches    = 0;
static HANDLE g_hCon         = INVALID_HANDLE_VALUE;
static std::string g_ScanTime;

// Live counters (touched by worker threads -> Interlocked*)
static volatile LONG   c_Queued      = 0;
static volatile LONG   c_Done        = 0;
static volatile LONG   c_Suspicious  = 0;
static volatile LONG   c_Matches     = 0;
static volatile LONG   c_Unreadable  = 0;   // open failed / empty / too big
static volatile LONG   c_SkippedDirs = 0;
static volatile LONG   c_SkippedFiles= 0;   // cloud placeholders
static volatile LONG   c_ApiOnly     = 0;   // only generic API names found (hidden)
static volatile LONG64 c_Bytes       = 0;
static CRITICAL_SECTION g_ResultsCS;


// ============================================================
//  CONSOLE HELPERS
// ============================================================
#define COL_DEFAULT  (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE)
#define COL_WHITE_B  (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY)
#define COL_RED_B    (FOREGROUND_RED|FOREGROUND_INTENSITY)
#define COL_GREEN_B  (FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define COL_YELLOW_B (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define COL_CYAN_B   (FOREGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY)
#define COL_GREY     (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE)
#define COL_RED      (FOREGROUND_RED)

void SetCol(WORD c) { SetConsoleTextAttribute(g_hCon, c); }

// ============================================================
//  SEVERITY / CATEGORY
// ============================================================
Severity GetSeverity(const std::string& category) {
    if (category == "CHEAT_TOOL"   ) return SEV_CRITICAL;
    if (category == "INJECTOR"     ) return SEV_CRITICAL;
    if (category == "BYPASS_AC"    ) return SEV_CRITICAL;
    if (category == "ROOTKIT"      ) return SEV_CRITICAL;
    if (category == "AIMBOT"       ) return SEV_CRITICAL;
    if (category == "WALLHACK"     ) return SEV_CRITICAL;
    if (category == "SUSP_URL"     ) return SEV_HIGH;
    if (category == "SUSP_PATH"    ) return SEV_HIGH;
    if (category == "SUSP_API"     ) return SEV_MEDIUM;
    if (category == "PACKER"       ) return SEV_MEDIUM;
    return SEV_LOW;
}

std::string GetCategory(const std::string& kw) {
    std::string kl = kw;
    std::transform(kl.begin(), kl.end(), kl.begin(), ::tolower);

    if (kl.find("aimbot")!=std::string::npos || kl.find("aim_bot")!=std::string::npos ||
        kl.find("triggerbot")!=std::string::npos || kl.find("boneaim")!=std::string::npos ||
        kl.find("silentaim")!=std::string::npos || kl.find("autoaim")!=std::string::npos)
        return "AIMBOT";

    if (kl.find("wallhack")!=std::string::npos || kl.find("esp")!=std::string::npos ||
        kl.find("skeleton")!=std::string::npos || kl.find("boxesp")!=std::string::npos)
        return "WALLHACK";

    if (kl.find("inject")!=std::string::npos || kl.find("manualmap")!=std::string::npos ||
        kl.find("remotethread")!=std::string::npos || kl.find("ldrload")!=std::string::npos)
        return "INJECTOR";

    if (kl.find("cheatengine")!=std::string::npos || kl.find("gameguardian")!=std::string::npos ||
        kl.find("wearedevs")!=std::string::npos || kl.find("aimware")!=std::string::npos ||
        kl.find("xenos")!=std::string::npos || kl.find("ollydbg")!=std::string::npos ||
        kl.find("x64dbg")!=std::string::npos || kl.find("ghidra")!=std::string::npos)
        return "CHEAT_TOOL";

    if (kl.find("bypassac")!=std::string::npos || kl.find("bypass_ac")!=std::string::npos ||
        kl.find("killac")!=std::string::npos || kl.find("disableac")!=std::string::npos ||
        kl.find("anticheaat")!=std::string::npos)
        return "BYPASS_AC";

    if (kl.find("ssdthook")!=std::string::npos || kl.find("kernelhook")!=std::string::npos ||
        kl.find("hideprocess")!=std::string::npos || kl.find("dkom")!=std::string::npos ||
        kl.find("infinityhook")!=std::string::npos)
        return "ROOTKIT";

    if (kl.find("upx!")!=std::string::npos || kl.find("themida")!=std::string::npos ||
        kl.find("vmprotect")!=std::string::npos || kl.find("vmp_begin")!=std::string::npos)
        return "PACKER";

    return "SUSPICIOUS";
}

// ============================================================
//  KEYWORD TABLE  (case-insensitive duplicates removed)
//  v1.0 matched case-insensitively but still listed
//  "aimbot" / "AimBot" / "AIMBOT" as three separate hits.
// ============================================================
struct Keyword {
    std::string text;
    std::string category;
    Severity    severity;
    bool        wide;        // also search as UTF-16LE
    bool        boundary;    // require a non-alnum char on both sides (rejects hits
                              // that are really substrings of an unrelated identifier,
                              // e.g. "BypassAC" inside "...BypassAccessCheck")
};
static std::vector<Keyword> g_Keywords;

static std::string ToLowerA(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    return s;
}

static int g_iOpenProc = -1, g_iWPM = -1, g_iCRT = -1, g_iNtCTE = -1, g_iRtlCUT = -1;

static void BuildKeywordTable() {
    // Windows API names appear in almost every legitimate program (and are
    // exported by kernel32 / ntdll), so they only score 1 point and never
    // put a file in the report on their own. Real signal comes from cheat
    // names, PE structure (packers) and hashes.
    static const char* WEAK[] = {
        "createremotethread","ntcreatethreadex","rtlcreateuserthread","ldrloaddll","ldrploaddll",
        "writeprocessmemory","virtualallocex","virtualprotect","ntprotectvirtualmemory",
        "zwprotectvirtualmemory","ntwritevirtualmemory","zwwritevirtualmemory",
        "ntreadvirtualmemory","ntallocatevirtualmemory","zwallocatevirtualmemory" };
    std::set<std::string> weak(WEAK, WEAK + sizeof(WEAK) / sizeof(WEAK[0]));
    std::set<std::string> seen;
    auto isWordChar = [](unsigned char c) { return std::isalnum(c) || c == '_'; };
    auto add = [&](const std::vector<std::string>& list, bool wide, bool api) {
        for (auto& kw : list) {
            if (kw.empty()) continue;
            std::string low = ToLowerA(kw);
            if (!seen.insert(low).second) continue;
            Keyword k;
            k.text     = kw;
            k.category = GetCategory(kw);
            k.severity = GetSeverity(k.category);
            k.wide     = wide;
            if (api || weak.count(low)) { k.category = "SUSP_API"; k.severity = SEV_INFO; }
            // Short keywords made only of letters/digits/underscore (no dot, slash,
            // space, "!", ...) can appear as a fragment of an unrelated identifier
            // ("BypassAC" inside "FileRenameInformationBypassAccessCheck"), so those
            // are only counted when both neighbouring characters are non-word chars.
            bool allWord = !kw.empty();
            for (unsigned char c : kw) if (!isWordChar(c)) { allWord = false; break; }
            k.boundary = allWord && kw.size() <= 14 && !api;
            g_Keywords.push_back(k);
        }
    };
    add(CHEAT_STRINGS,    true,  false);
    add(SUSPICIOUS_URLS,  true,  false);
    add(SUSPICIOUS_PATHS, true,  false);
    add(SUSPICIOUS_API,   false, true);   // API names: ASCII only (high volume)

    auto idx = [&](const char* n) -> int {
        for (size_t i = 0; i < g_Keywords.size(); i++) if (ToLowerA(g_Keywords[i].text) == n) return (int)i;
        return -1;
    };
    g_iOpenProc = idx("openprocess");        g_iWPM    = idx("writeprocessmemory");
    g_iCRT      = idx("createremotethread"); g_iNtCTE  = idx("ntcreatethreadex");
    g_iRtlCUT   = idx("rtlcreateuserthread");
}

// ============================================================
//  FAST MULTI-PATTERN MATCHER  (Aho-Corasick, case-insensitive)
// ============================================================
//  Every keyword is compiled into ONE automaton, so a file needs
//  a single pass no matter how many keywords exist. Bytes are
//  mapped to a small "class" alphabet (upper/lower case share a
//  class), which keeps the transition table small and cache-hot.
// BEGIN_MATCHER
class Matcher {
public:
    struct Out { int kw; int len; };
    static constexpr uint32_t FLAG = 0x80000000u;   // "this state has output"

    void Build(const std::vector<std::string>& texts, const std::vector<bool>& wide)
    {
        auto fold = [](unsigned char c) -> unsigned char {
            return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
        };

        // 1) byte classes. Class 0 = byte that appears in no keyword.
        bool used[256] = {};
        for (size_t i = 0; i < texts.size(); i++) {
            for (unsigned char c : texts[i]) used[fold(c)] = true;
            if (wide[i]) used[0] = true;
        }
        std::memset(cls_, 0, sizeof(cls_));
        nc_ = 1;
        for (int c = 0; c < 256; c++)
            if (used[c]) cls_[c] = (uint8_t)nc_++;
        for (int c = 'A'; c <= 'Z'; c++) cls_[c] = cls_[c + 32];

        // 2) trie: ASCII form, plus UTF-16LE form "a\0b\0c\0" when wide
        std::vector<int> child(nc_, -1);
        std::vector<std::vector<Out>> stOut(1);
        for (size_t i = 0; i < texts.size(); i++) {
            for (int form = 0; form < (wide[i] ? 2 : 1); form++) {   // 0 = ASCII, 1 = UTF-16LE
                std::vector<uint8_t> bytes;
                for (unsigned char c : texts[i]) {
                    bytes.push_back(c);
                    if (form == 1) bytes.push_back(0);
                }
                int s = 0;
                for (uint8_t b : bytes) {
                    size_t idx = (size_t)s * nc_ + cls_[b];
                    int nx = child[idx];
                    if (nx < 0) {
                        nx = (int)stOut.size();
                        child.resize(child.size() + nc_, -1);
                        stOut.emplace_back();
                        child[idx] = nx;
                    }
                    s = nx;
                }
                stOut[s].push_back(Out{ (int)i, (int)bytes.size() });
            }
        }

        // 3) failure links + full DFA (breadth first)
        size_t ns = stOut.size();
        std::vector<int>      fail(ns, 0);
        std::vector<uint32_t> dfa(ns * nc_, 0);
        std::vector<int>      queue;
        queue.reserve(ns);
        for (uint32_t k = 0; k < nc_; k++) {
            int c = child[k];
            if (c >= 0) { fail[c] = 0; dfa[k] = (uint32_t)c; queue.push_back(c); }
            else dfa[k] = 0;
        }
        for (size_t qi = 0; qi < queue.size(); qi++) {
            int u = queue[qi];
            for (const Out& o : stOut[fail[u]]) stOut[u].push_back(o);   // inherit outputs
            for (uint32_t k = 0; k < nc_; k++) {
                int c = child[(size_t)u * nc_ + k];
                uint32_t f = dfa[(size_t)fail[u] * nc_ + k];
                if (c >= 0) { fail[c] = (int)f; dfa[(size_t)u * nc_ + k] = (uint32_t)c; queue.push_back(c); }
                else dfa[(size_t)u * nc_ + k] = f;
            }
        }

        // 4) flatten outputs, pre-multiply states by nc_, flag output states
        outBeg_.assign(ns + 1, 0);
        outs_.clear();
        for (size_t s = 0; s < ns; s++) {
            outBeg_[s + 1] = outBeg_[s] + (uint32_t)stOut[s].size();
            for (const Out& o : stOut[s]) outs_.push_back(o);
        }
        tbl_.assign(ns * nc_, 0);
        for (size_t i = 0; i < tbl_.size(); i++) {
            uint32_t t = dfa[i];
            uint32_t v = t * nc_;
            if (outBeg_[t + 1] != outBeg_[t]) v |= FLAG;
            tbl_[i] = v;
        }
    }

    // Feed one chunk. 'sm' is the automaton state carried over from the
    // previous chunk (start with 0). firstOff[kw] gets the file offset
    // of the first hit (only written while it is still < 0).
    uint32_t Feed(const uint8_t* p, size_t n, uint32_t sm,
                  int64_t base, int64_t* firstOff) const
    {
        const uint32_t* T = tbl_.data();
        const uint8_t*  C = cls_;
        for (size_t i = 0; i < n; i++) {
            uint32_t v = T[sm + C[p[i]]];
            sm = v & ~FLAG;
            if (v & FLAG) {
                uint32_t st = sm / nc_;
                for (uint32_t j = outBeg_[st]; j < outBeg_[st + 1]; j++) {
                    const Out& o = outs_[j];
                    if (firstOff[o.kw] < 0)
                        firstOff[o.kw] = base + (int64_t)i + 1 - o.len;
                }
            }
        }
        return sm;
    }

private:
    uint8_t               cls_[256];
    uint32_t              nc_ = 1;
    std::vector<uint32_t> tbl_;
    std::vector<uint32_t> outBeg_;
    std::vector<Out>      outs_;
};
// END_MATCHER

// ============================================================
//  SHA-256  (VirusTotal links + known-bad hash list)
// ============================================================
// BEGIN_SHA
class Sha256 {
public:
    Sha256() { Reset(); }
    void Reset() {
        static const uint32_t I[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
        std::memcpy(h_, I, sizeof(h_));
        n_ = 0; total_ = 0;
    }
    void Update(const uint8_t* p, size_t len) {
        total_ += len;
        if (n_ == 0) while (len >= 64) { Block(p); p += 64; len -= 64; }
        while (len > 0) {
            size_t take = 64 - n_; if (take > len) take = len;
            std::memcpy(buf_ + n_, p, take);
            n_ += take; p += take; len -= take;
            if (n_ == 64) { Block(buf_); n_ = 0; }
        }
    }
    std::string Final() {
        uint64_t bits = total_ * 8;
        uint8_t pad = 0x80; Update(&pad, 1);
        uint8_t z = 0;      while (n_ != 56) Update(&z, 1);
        uint8_t l[8];
        for (int i = 0; i < 8; i++) l[i] = (uint8_t)(bits >> (56 - 8 * i));
        Update(l, 8);
        static const char* hx = "0123456789abcdef";
        std::string out;
        for (int i = 0; i < 8; i++)
            for (int s = 28; s >= 0; s -= 4) out += hx[(h_[i] >> s) & 0xF];
        return out;
    }
private:
    uint32_t h_[8]; uint8_t buf_[64]; size_t n_; uint64_t total_;
    static uint32_t R(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    void Block(const uint8_t* p) {
        static const uint32_t K[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)p[4*i] << 24) | ((uint32_t)p[4*i+1] << 16) | ((uint32_t)p[4*i+2] << 8) | p[4*i+3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = R(w[i-15], 7) ^ R(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = R(w[i-2], 17) ^ R(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h_[0], b=h_[1], c=h_[2], d=h_[3], e=h_[4], f=h_[5], g=h_[6], h=h_[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h + (R(e,6) ^ R(e,11) ^ R(e,25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
            uint32_t t2 = (R(a,2) ^ R(a,13) ^ R(a,22)) + ((a & b) ^ (a & c) ^ (b & c));
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h_[0]+=a; h_[1]+=b; h_[2]+=c; h_[3]+=d; h_[4]+=e; h_[5]+=f; h_[6]+=g; h_[7]+=h;
    }
};
// END_SHA

// ============================================================
//  PE STRUCTURE ANALYSIS  (packer / protector detection)
// ============================================================
//  String matching cannot see inside packed or encrypted files.
//  Packers leave structural fingerprints instead, which is what
//  AV engines flag as "Packed.UPX / Packed.VMProtect ...":
//    - known packer section names (.UPX0, .vmp0, .themida ...)
//    - the entry point sits in a near-random (high entropy) section
//    - executable sections that are EMPTY on disk (code is
//      unpacked into them at run time)
//    - and: a packed file inside C:\Windows\System32 is never
//      legitimate (Microsoft does not pack its files)
// BEGIN_PE
struct PESection { char name[9]; uint32_t vsize, vaddr, rawsize, rawptr, chars; };
struct PEInfo {
    bool valid = false, is64 = false, signedCert = false;
    uint32_t ep = 0;
    int nsec = 0;
    int epSec = -1;      // section that contains the entry point
    int exSec = -1;      // largest executable section (by raw size)
    PESection sec[96];
};
struct EntRange { int64_t start = 0, end = 0; uint64_t total = 0; uint32_t hist[256]; };
struct PEFinding { std::string category; std::string text; Severity sev; };

static uint32_t RdU32(const uint8_t* p) { uint32_t v; std::memcpy(&v, p, 4); return v; }
static uint16_t RdU16(const uint8_t* p) { uint16_t v; std::memcpy(&v, p, 2); return v; }

// Parse the PE headers from the first bytes of the file.
static void ParsePE(const uint8_t* b, size_t n, PEInfo& pi)
{
    pi.valid = false;
    if (n < 0x100 || b[0] != 'M' || b[1] != 'Z') return;
    size_t pe = RdU32(b + 0x3C);
    if (pe < 0x40 || pe + 24 > n) return;
    if (RdU32(b + pe) != 0x00004550) return;                 // "PE\0\0"
    uint16_t nsec = RdU16(b + pe + 6);
    uint16_t optSize = RdU16(b + pe + 20);
    size_t opt = pe + 24;
    if (optSize < 96 || opt + optSize > n) return;
    uint16_t magic = RdU16(b + opt);
    if (magic != 0x10b && magic != 0x20b) return;
    pi.is64 = (magic == 0x20b);
    pi.ep   = RdU32(b + opt + 16);
    size_t ddOff = opt + (pi.is64 ? 112 : 96);
    uint32_t nDD = RdU32(b + opt + (pi.is64 ? 108 : 92));
    pi.signedCert = false;
    if (nDD > 4 && ddOff + 5 * 8 <= opt + optSize)
        pi.signedCert = RdU32(b + ddOff + 4 * 8 + 4) != 0;    // Security directory = embedded certificate
    size_t st = opt + optSize;
    if (nsec == 0 || nsec > 96 || st + (size_t)nsec * 40 > n) return;
    pi.nsec = nsec;
    pi.epSec = pi.exSec = -1;
    uint32_t bestRaw = 0;
    for (int i = 0; i < nsec; i++) {
        const uint8_t* s = b + st + (size_t)i * 40;
        PESection& d = pi.sec[i];
        std::memcpy(d.name, s, 8); d.name[8] = 0;
        d.vsize = RdU32(s + 8);   d.vaddr = RdU32(s + 12);
        d.rawsize = RdU32(s + 16); d.rawptr = RdU32(s + 20);
        d.chars = RdU32(s + 36);
        uint32_t span = d.vsize > d.rawsize ? d.vsize : d.rawsize;
        if (pi.ep && pi.epSec < 0 && pi.ep >= d.vaddr && pi.ep < (uint64_t)d.vaddr + span) pi.epSec = i;
        if ((d.chars & 0x20000000u) && d.rawsize > bestRaw) { bestRaw = d.rawsize; pi.exSec = i; }
    }
    pi.valid = true;
}

static void HistAdd(EntRange& r, const uint8_t* b, size_t n, int64_t base)
{
    int64_t lo = std::max<int64_t>(r.start, base);
    int64_t hi = std::min<int64_t>(r.end, base + (int64_t)n);
    if (lo >= hi) return;
    for (int64_t i = lo; i < hi; i++) r.hist[b[i - base]]++;
    r.total += (uint64_t)(hi - lo);
}

static double EntropyOf(const uint32_t* hist, uint64_t total)
{
    if (total == 0) return -1.0;
    double e = 0;
    for (int i = 0; i < 256; i++) {
        if (!hist[i]) continue;
        double p = (double)hist[i] / (double)total;
        e -= p * std::log2(p);
    }
    return e;
}

static std::string SecName(const PESection& s) {
    std::string n(s.name);
    for (auto& c : n) if ((unsigned char)c < 32 || (unsigned char)c > 126) c = '?';
    return n;
}

static const char* PackerOfSection(const char* raw)
{
    struct P { const char* n; const char* label; };
    static const P T[] = {
        {"upx0","UPX"},{"upx1","UPX"},{"upx2","UPX"},
        {"vmp0","VMProtect"},{"vmp1","VMProtect"},{"vmp2","VMProtect"},{"vmp3","VMProtect"},
        {"themida","Themida"},{"winlice","WinLicense"},
        {"enigma1","Enigma Protector"},{"enigma2","Enigma Protector"},
        {"aspack","ASPack"},{"adata","ASPack"},
        {"mpress1","MPRESS"},{"mpress2","MPRESS"},
        {"petite","Petite"},{"pec1","PECompact"},{"pec2","PECompact"},{"pecompact","PECompact"},
        {"nsp0","NsPack"},{"nsp1","NsPack"},{"nsp2","NsPack"},
        {"yp","Y0da Protector"},{"svkp","SVKP"},{"pebundle","PEBundle"},{"pespin","PESpin"},
        {"obsidium","Obsidium"},{"rlpack","RLPack"},{"packed","unknown packer"},
    };
    std::string n(raw);
    for (auto& c : n) if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    if (!n.empty() && n[0] == '.') n.erase(0, 1);
    for (auto& t : T) if (n == t.n) return t.label;
    return nullptr;
}

// epEnt / exEnt: entropy of the entry-point section / largest executable
// section (-1 = unknown). sysDir: file lives in C:\Windows\System32 & co.
static void AnalyzePE(const PEInfo& pi, double epEnt, double exEnt, bool sysDir,
                      std::vector<PEFinding>& out, std::string& info)
{
    char tmp[256];
    std::string epName = (pi.epSec >= 0) ? SecName(pi.sec[pi.epSec]) : std::string("-");
    snprintf(tmp, sizeof(tmp), "Sections: %d | Entry point in: %s", pi.nsec, epName.c_str());
    info = tmp;
    if (epEnt >= 0) { snprintf(tmp, sizeof(tmp), " | EP section entropy: %.2f", epEnt); info += tmp; }
    if (exEnt >= 0 && pi.exSec != pi.epSec) {
        snprintf(tmp, sizeof(tmp), " | %s entropy: %.2f", SecName(pi.sec[pi.exSec]).c_str(), exEnt); info += tmp;
    }
    info += pi.signedCert ? " | Embedded signature: yes" : " | Embedded signature: none";

    // Signed files are usually commercial software -> one level lower
    Severity base = pi.signedCert ? SEV_MEDIUM : SEV_HIGH;
    bool packed = false;

    // 1) known packer / protector section names
    std::string names, labels;
    for (int i = 0; i < pi.nsec; i++) {
        const char* lb = PackerOfSection(pi.sec[i].name);
        if (!lb) continue;
        if (!names.empty()) names += ", ";
        names += SecName(pi.sec[i]);
        if (labels.find(lb) == std::string::npos) { if (!labels.empty()) labels += " / "; labels += lb; }
    }
    if (!names.empty()) {
        out.push_back({ "PACKED", "Packer section names: " + names + "  (" + labels + ")", base });
        packed = true;
    }

    // 2) entry point / main code section is almost random data
    bool epHigh = false;
    if (epEnt >= 7.2 && pi.epSec >= 0 && pi.sec[pi.epSec].rawsize >= 32768) {
        snprintf(tmp, sizeof(tmp), "Entry point is inside near-random data: section %s, entropy %.2f (compressed / encrypted code)",
                 epName.c_str(), epEnt);
        out.push_back({ "PACKED", tmp, base });
        epHigh = true; packed = true;
    }
    if (exEnt >= 7.3 && pi.exSec >= 0 && pi.sec[pi.exSec].rawsize >= 65536 && !(epHigh && pi.exSec == pi.epSec)) {
        snprintf(tmp, sizeof(tmp), "Executable section %s is near-random data (entropy %.2f)",
                 SecName(pi.sec[pi.exSec]).c_str(), exEnt);
        out.push_back({ "PACKED", tmp, base });
        packed = true;
    }

    // 3) executable sections that are empty on disk (filled at run time)
    for (int i = 0; i < pi.nsec; i++) {
        const PESection& s = pi.sec[i];
        if ((s.chars & 0x20000000u) && s.rawsize == 0 && s.vsize >= 0x10000 &&
            SecName(s) != ".textbss") {
            snprintf(tmp, sizeof(tmp), "Executable section %s is empty on disk (%u KB in memory) - code is unpacked at run time",
                     SecName(s).c_str(), (unsigned)(s.vsize / 1024));
            out.push_back({ "PACKED", tmp, SEV_MEDIUM });
            packed = true;
            break;
        }
    }

    // 4) packed file in the Windows system folder
    if (packed && sysDir && !pi.signedCert)
        out.push_back({ "PACKED_SYSDIR",
            "Packed/protected file inside a Windows system folder - Microsoft files are never packed", SEV_CRITICAL });
}
// END_PE

// ============================================================
//  KNOWN-BAD HASH LIST
// ============================================================
//  Built-in entries + an optional "hashes.txt" placed next to the .exe.
//  One entry per line:   <sha256>  [size in bytes]  [name]     (# = comment)
//   - with a size: the file is hashed only when its size matches (fast)
//   - without size: the file is hashed when it is already suspicious
struct BadHash { std::string name; ULONGLONG size; };
static std::map<std::string, BadHash> g_BadHashes;
static std::set<ULONGLONG>            g_BadSizes;

static bool IsHex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}
static void AddBadHash(std::string h, ULONGLONG size, const std::string& name) {
    h = ToLowerA(h);
    if (!IsHex64(h)) return;
    BadHash b; b.name = name; b.size = size;
    g_BadHashes[h] = b;
    if (size) g_BadSizes.insert(size);
}
static void LoadBadHashes() {
    // Confirmed on VirusTotal: trojan / dropper, packed (UPX-style)
    AddBadHash("8cf4db0316f3540403605ce48d0ca8e2a76ebe2b6db4636ad1ff4cc65348aee2", 10878976ULL,
               "Free_Panel.dll (VirusTotal: trojan/dropper, packed)");

    wchar_t exe[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (!n || n >= MAX_PATH) return;
    std::wstring p(exe, n);
    size_t sl = p.find_last_of(L"\\/");
    if (sl == std::wstring::npos) return;
    p = p.substr(0, sl + 1) + L"hashes.txt";

    HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    std::string txt; char tmp[4096]; DWORD rd = 0;
    while (ReadFile(h, tmp, sizeof(tmp), &rd, nullptr) && rd) txt.append(tmp, rd);
    CloseHandle(h);

    std::istringstream in(txt);
    std::string line;
    while (std::getline(in, line)) {
        size_t c = line.find('#');
        if (c != std::string::npos) line.erase(c);
        std::istringstream ls(line);
        std::vector<std::string> tok; std::string t;
        while (ls >> t) tok.push_back(t);
        if (tok.empty()) continue;
        ULONGLONG size = 0; size_t ni = 1;
        if (tok.size() > 1 && tok[1].find_first_not_of("0123456789") == std::string::npos) {
            size = _strtoui64(tok[1].c_str(), nullptr, 10); ni = 2;
        }
        std::string name;
        for (size_t i = ni; i < tok.size(); i++) { if (!name.empty()) name += " "; name += tok[i]; }
        AddBadHash(tok[0], size, name.empty() ? std::string("hashes.txt entry") : name);
    }
}

// ============================================================
//  WORK QUEUE + WORKER THREADS
// ============================================================
struct Job { std::wstring path; ULONGLONG size = 0; };

static Matcher            g_Matcher;
static std::deque<Job>    g_Queue;
static CRITICAL_SECTION   g_QCS;
static CONDITION_VARIABLE g_QCV;
static bool               g_EnumDone = false;
static bool               g_FastMode = false;

static const ULONGLONG MAX_FILE_SIZE = 100ULL * 1024 * 1024;   // same limit as v1.0
static const size_t    CHUNK_SIZE    = 4u << 20;               // 4 MB read chunks

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

static bool IsSystemDirPath(const std::wstring& path) {
    std::wstring low = path;
    for (auto& c : low) c = (wchar_t)towlower(c);
    return low.find(L"\\windows\\system32\\") != std::wstring::npos ||
           low.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
           low.find(L"\\windows\\sysnative\\") != std::wstring::npos;
}

static std::string HashFile(const std::wstring& path, std::vector<uint8_t>& buf) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::string();
    Sha256 s;
    for (;;) {
        DWORD rd = 0;
        if (!ReadFile(h, buf.data(), (DWORD)buf.size(), &rd, nullptr) || rd == 0) break;
        s.Update(buf.data(), rd);
    }
    CloseHandle(h);
    return s.Final();
}

// Re-reads a small window around a candidate match and confirms it is a
// real, delimited occurrence (both ASCII and UTF-16LE forms are tried,
// since the streaming matcher does not record which form hit).
static bool VerifyBoundary(const std::wstring& path, int64_t off, const std::string& kwLower)
{
    size_t alen = kwLower.size(), wlen = alen * 2;
    int64_t winStart = off > 1 ? off - 1 : 0;
    size_t  want = (size_t)(off - winStart) + wlen + 1;

    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return true;   // can't verify -> keep the hit
    LARGE_INTEGER li; li.QuadPart = winStart;
    SetFilePointerEx(h, li, nullptr, FILE_BEGIN);
    std::vector<uint8_t> w(want);
    DWORD rd = 0;
    BOOL ok = ReadFile(h, w.data(), (DWORD)want, &rd, nullptr);
    CloseHandle(h);
    if (!ok) return true;
    w.resize(rd);

    size_t lead = (size_t)(off - winStart);              // bytes before the match in w[]
    auto isWord = [](int c) { return c >= 0 && (std::isalnum(c) || c == '_'); };
    auto eqi    = [](uint8_t a, uint8_t b) { return std::tolower(a) == std::tolower(b); };

    // ASCII form
    if (lead + alen <= w.size()) {
        bool body = true;
        for (size_t i = 0; i < alen; i++) if (!eqi(w[lead + i], (uint8_t)kwLower[i])) { body = false; break; }
        if (body) {
            bool preOk  = (lead == 0) || !isWord(w[lead - 1]);
            bool postOk = (lead + alen >= w.size()) || !isWord(w[lead + alen]);
            if (preOk && postOk) return true;
        }
    }
    // UTF-16LE form
    if (lead + wlen <= w.size()) {
        bool body = true;
        for (size_t i = 0; i < alen; i++)
            if (!eqi(w[lead + 2*i], (uint8_t)kwLower[i]) || w[lead + 2*i + 1] != 0) { body = false; break; }
        if (body) {
            bool preOk  = (lead == 0) || !(isWord(w[lead - 1]) && (lead < 2 || w[lead - 2] == 0));
            bool postOk = (lead + wlen >= w.size()) || !isWord(w[lead + wlen]);
            if (preOk && postOk) return true;
        }
    }
    return false;
}

static void ScanOne(const Job& job, std::vector<uint8_t>& buf, std::vector<int64_t>& firstOff)
{
    HANDLE h = CreateFileW(job.path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) { InterlockedIncrement(&c_Unreadable); return; }

    std::fill(firstOff.begin(), firstOff.end(), (int64_t)-1);

    PEInfo   pi;
    EntRange er[2];
    int      nEr = 0, erEp = -1, erEx = -1;
    uint32_t sm    = 0;        // automaton state (carried across chunks)
    int64_t  base  = 0;        // file offset of buf[0]
    bool     first = true;
    bool     isPE  = true;

    for (;;) {
        DWORD rd = 0;
        if (!ReadFile(h, buf.data(), (DWORD)buf.size(), &rd, nullptr) || rd == 0) break;
        if (first) {
            first = false;
            if (rd < 2 || buf[0] != 'M' || buf[1] != 'Z') { isPE = false; break; }   // not a PE file
            ParsePE(buf.data(), rd, pi);
            if (pi.valid) {
                // entropy is measured on the entry-point section and the biggest code section
                auto addRange = [&](int si) -> int {
                    if (si < 0) return -1;
                    const PESection& s = pi.sec[si];
                    if (s.rawsize < 4096 || s.rawptr == 0) return -1;
                    for (int k = 0; k < nEr; k++) if (er[k].start == (int64_t)s.rawptr) return k;
                    er[nEr].start = s.rawptr;
                    er[nEr].end   = (int64_t)s.rawptr + s.rawsize;
                    er[nEr].total = 0;
                    std::memset(er[nEr].hist, 0, sizeof(er[nEr].hist));
                    return nEr++;
                };
                erEp = addRange(pi.epSec);
                erEx = addRange(pi.exSec);
            }
        }
        sm = g_Matcher.Feed(buf.data(), rd, sm, base, firstOff.data());
        for (int k = 0; k < nEr; k++) HistAdd(er[k], buf.data(), rd, base);
        base += rd;
    }
    CloseHandle(h);
    InterlockedExchangeAdd64(&c_Bytes, base);
    if (!isPE) return;

    // ---- collect findings
    FileResult r;
    auto addMatch = [&](const std::string& cat, const std::string& text, Severity sev, size_t off) {
        StringMatch m;
        m.keyword = text; m.category = cat; m.severity = sev; m.offset = off;
        r.matches.push_back(m);
        r.score += PointsFor(sev);
        if (sev > r.maxSeverity) r.maxSeverity = sev;
    };

    for (size_t k = 0; k < g_Keywords.size(); k++) {
        if (firstOff[k] < 0) continue;
        const Keyword& kw = g_Keywords[k];
        if (kw.boundary && !VerifyBoundary(job.path, firstOff[k], ToLowerA(kw.text))) continue;
        addMatch(kw.category, kw.text, kw.severity, (size_t)firstOff[k]);
    }

    bool sysDir = IsSystemDirPath(job.path);
    if (pi.valid) {
        double epEnt = (erEp >= 0) ? EntropyOf(er[erEp].hist, er[erEp].total) : -1.0;
        double exEnt = (erEx >= 0) ? EntropyOf(er[erEx].hist, er[erEx].total) : -1.0;
        std::vector<PEFinding> pf;
        AnalyzePE(pi, epEnt, exEnt, sysDir, pf, r.peInfo);
        for (auto& f : pf) addMatch(f.category, f.text, f.sev, 0);
        r.isSigned = pi.signedCert;
    }

    // Classic injector API chain (skipped in system folders: kernel32/ntdll export these names)
    auto has = [&](int i) { return i >= 0 && firstOff[i] >= 0; };
    if (!sysDir && has(g_iOpenProc) && has(g_iWPM) && (has(g_iCRT) || has(g_iNtCTE) || has(g_iRtlCUT)))
        addMatch("INJECT_COMBO", "Process-injection API chain: OpenProcess + WriteProcessMemory + remote thread", SEV_MEDIUM, 0);

    // ---- SHA-256 (only where it matters) + known-bad list
    if (g_BadSizes.count(job.size) || r.maxSeverity >= SEV_MEDIUM) {
        std::string hx = HashFile(job.path, buf);
        if (!hx.empty()) {
            r.sha256 = hx;
            auto it = g_BadHashes.find(hx);
            if (it != g_BadHashes.end())
                addMatch("KNOWN_BAD", "Known malware hash: " + it->second.name, SEV_CRITICAL, 0);
        }
    }

    // Files that only contain generic Windows API names are not reported (pure noise)
    if (r.maxSeverity < SEV_LOW) {
        if (r.score > 0) InterlockedIncrement(&c_ApiOnly);
        return;
    }

    r.path = WideToUtf8(job.path);
    size_t sl  = r.path.rfind('\\');
    r.name     = (sl == std::string::npos) ? r.path : r.path.substr(sl + 1);
    size_t dot = r.name.rfind('.');
    r.ext      = (dot == std::string::npos) ? std::string() : ToLowerA(r.name.substr(dot));
    r.fileSize = (size_t)job.size;

    InterlockedIncrement(&c_Suspicious);
    InterlockedExchangeAdd(&c_Matches, (LONG)r.matches.size());
    EnterCriticalSection(&g_ResultsCS);
    g_Results.push_back(std::move(r));
    LeaveCriticalSection(&g_ResultsCS);
}

static DWORD WINAPI WorkerProc(LPVOID)
{
    std::vector<uint8_t> buf(CHUNK_SIZE);
    std::vector<int64_t> firstOff(g_Keywords.size());
    for (;;) {
        Job job;
        EnterCriticalSection(&g_QCS);
        while (g_Queue.empty() && !g_EnumDone)
            SleepConditionVariableCS(&g_QCV, &g_QCS, INFINITE);
        if (g_Queue.empty()) { LeaveCriticalSection(&g_QCS); break; }   // finished
        job = std::move(g_Queue.front());
        g_Queue.pop_front();
        LeaveCriticalSection(&g_QCS);

        ScanOne(job, buf, firstOff);
        InterlockedIncrement(&c_Done);
    }
    return 0;
}

// ============================================================
//  PROGRESS LINE (main thread only)
// ============================================================
static void Progress(bool enumerating)
{
    static ULONGLONG last = 0;
    static int spin = 0;
    ULONGLONG now = GetTickCount64();
    if (now - last < 100) return;
    last = now;
    static const char sp[] = { '|', '/', '-', '\\' };

    SetCol(COL_CYAN_B);
    printf("\r  [%c] %s | Queued: %-7ld Scanned: %-7ld Suspicious: %-4ld Data: %-6.0f MB   ",
        sp[(spin++) & 3], enumerating ? "Scanning " : "Finishing",
        (long)c_Queued, (long)c_Done, (long)c_Suspicious,
        (double)c_Bytes / (1024.0 * 1024.0));
    fflush(stdout);
    SetCol(COL_DEFAULT);
}

// ============================================================
//  DIRECTORY SCANNER (Recursive, feeds the work queue)
// ============================================================
// Paths to skip (compared lower-case, with a trailing backslash)
static const std::vector<std::string> SKIP_PATHS = {
    "\\Windows\\WinSxS\\",
    "\\Windows\\servicing\\",
    "\\Windows\\assembly\\",
    "$Recycle.Bin",
    "\\MicrosoftEdge\\",
    "\\Windows\\Microsoft.NET\\",
};
static std::vector<std::wstring> g_SkipLower;

static void InitSkipList() {
    for (auto& s : SKIP_PATHS) {
        std::wstring w(s.begin(), s.end());
        for (auto& ch : w) ch = (wchar_t)towlower(ch);
        g_SkipLower.push_back(w);
    }
}

static bool ShouldSkipDir(const std::wstring& dirPath) {
    std::wstring low = dirPath + L"\\";
    for (auto& ch : low) ch = (wchar_t)towlower(ch);
    for (auto& s : g_SkipLower)
        if (low.find(s) != std::wstring::npos) return true;
    // --fast: skip <drive>:\Windows entirely (Microsoft system files)
    if (g_FastMode && low.find(L":\\windows\\") != std::wstring::npos) return true;
    return false;
}

static bool IsScanExt(const wchar_t* dot) {
    return _wcsicmp(dot, L".exe") == 0 || _wcsicmp(dot, L".dll") == 0 || _wcsicmp(dot, L".sys") == 0;
}

static void ScanDirectory(const std::wstring& dir, int depth)
{
    if (depth > 8) return;                       // max depth (same as v1.0)
    if (ShouldSkipDir(dir)) { InterlockedIncrement(&c_SkippedDirs); return; }
    Progress(true);

    const DWORD OFFLINE_MASK = FILE_ATTRIBUTE_OFFLINE | 0x00400000 /*RECALL_ON_DATA_ACCESS*/
                             | 0x00040000 /*RECALL_ON_OPEN*/;

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW((dir + L"\\*").c_str(),
        (FINDEX_INFO_LEVELS)1 /*FindExInfoBasic: no 8.3 names*/, &fd,
        FindExSearchNameMatch, nullptr, 2 /*FIND_FIRST_EX_LARGE_FETCH*/);
    if (h == INVALID_HANDLE_VALUE) return;

    std::vector<std::wstring> subdirs;
    do {
        const wchar_t* n = fd.cFileName;
        if (n[0] == L'.' && (n[1] == 0 || (n[1] == L'.' && n[2] == 0))) continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // junctions / symlinks: avoids endless loops and double scanning
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            subdirs.push_back(dir + L"\\" + n);
            continue;
        }

        const wchar_t* dot = wcsrchr(n, L'.');
        if (!dot || !IsScanExt(dot)) continue;

        // OneDrive etc. placeholders: reading them would trigger a download
        if (fd.dwFileAttributes & OFFLINE_MASK) { InterlockedIncrement(&c_SkippedFiles); continue; }

        ULONGLONG size = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        if (size == 0 || size > MAX_FILE_SIZE) { InterlockedIncrement(&c_Unreadable); continue; }

        Job j;
        j.path = dir + L"\\" + n;
        j.size = size;
        EnterCriticalSection(&g_QCS);
        g_Queue.push_back(std::move(j));
        LeaveCriticalSection(&g_QCS);
        InterlockedIncrement(&c_Queued);
        WakeConditionVariable(&g_QCV);
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    for (auto& s : subdirs) ScanDirectory(s, depth + 1);
}

// ============================================================
//  HTML REPORT GENERATOR
// ============================================================
std::string HtmlEsc(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c=='&') o+="&amp;"; else if (c=='<') o+="&lt;";
        else if (c=='>') o+="&gt;"; else if (c=='"') o+="&quot;";
        else o+=c;
    }
    return o;
}

std::string SevColor(Severity s) {
    switch(s) {
        case SEV_CRITICAL: return "#ff2244";
        case SEV_HIGH:     return "#ff6622";
        case SEV_MEDIUM:   return "#ffcc00";
        case SEV_LOW:      return "#88cc44";
        default:           return "#44aaff";
    }
}
std::string SevText(Severity s) {
    switch(s) {
        case SEV_CRITICAL: return "CRITICAL";
        case SEV_HIGH:     return "HIGH";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_LOW:      return "LOW";
        default:           return "INFO";
    }
}

void GenerateReport(const std::wstring& outPath) {
    // Sort by score descending
    std::sort(g_Results.begin(), g_Results.end(),
        [](const FileResult& a, const FileResult& b){ return a.score != b.score ? a.score > b.score : a.path < b.path; });

    int crit=0,high=0,med=0,low=0;
    for (auto& r : g_Results) {
        switch(r.maxSeverity) {
            case SEV_CRITICAL:crit++;break; case SEV_HIGH:high++;break;
            case SEV_MEDIUM:med++;break; default:low++;break;
        }
    }

    // Risk level
    int totalScore = 0;
    for (auto& r : g_Results) totalScore += r.score;
    std::string riskLevel="CLEAN", riskColor="#00ff88";
    if(totalScore>=200){riskLevel="CRITICAL RISK";riskColor="#ff2244";}
    else if(totalScore>=80){riskLevel="HIGH RISK";riskColor="#ff6622";}
    else if(totalScore>=30){riskLevel="MEDIUM RISK";riskColor="#ffcc00";}
    else if(totalScore>=5){riskLevel="LOW RISK";riskColor="#88ff44";}

    // Build rows
    std::string fileRows;
    for (auto& r : g_Results) {
        std::string sc = SevColor(r.maxSeverity);
        std::string st = SevText(r.maxSeverity);
        std::string rc = (r.maxSeverity==SEV_CRITICAL)?"class='cr'":
                         (r.maxSeverity==SEV_HIGH)?"class='hi'":"";

        // Match list
        std::string matchList;
        std::map<std::string,std::vector<std::string>> byCat;
        for (auto& m : r.matches) byCat[m.category].push_back(m.keyword);
        for (auto& kv : byCat) {
            matchList += "<div class='cat-grp'><span class='cat-lbl'>" +
                HtmlEsc(kv.first) + "</span>";
            for (auto& kw : kv.second)
                matchList += "<span class='kw'>" + HtmlEsc(kw) + "</span>";
            matchList += "</div>";
        }
        if (!r.peInfo.empty())
            matchList += "<div class='cat-grp'><span class='cat-lbl'>PE INFO</span><span class='kw'>" +
                HtmlEsc(r.peInfo) + "</span></div>";
        if (!r.sha256.empty())
            matchList += "<div class='cat-grp'><span class='cat-lbl'>SHA-256</span>"
                "<a class='kw' target='_blank' rel='noopener' href='https://www.virustotal.com/gui/file/" + r.sha256 +
                "'>" + r.sha256 + "</a><span class='kw'>click = open on VirusTotal</span></div>";

        // File size
        char szBuf[32];
        if (r.fileSize < 1024) snprintf(szBuf,sizeof(szBuf),"%zu B",r.fileSize);
        else if (r.fileSize < 1024*1024) snprintf(szBuf,sizeof(szBuf),"%.1f KB",r.fileSize/1024.0);
        else snprintf(szBuf,sizeof(szBuf),"%.1f MB",r.fileSize/(1024.0*1024));

        fileRows +=
            "<tr " + std::string(rc) + " onclick='tog(\"m" +
            std::to_string(&r - &g_Results[0]) + "\")'>"
            "<td><span class='badge' style='background:"+sc+";color:#000'>"+st+"</span></td>"
            "<td class='fn'>" + HtmlEsc(r.name) + "</td>"
            "<td class='ext'><span class='ext-badge'>" + HtmlEsc(r.ext) + "</span></td>"
            "<td class='score'><b>" + std::to_string(r.score) + "</b></td>"
            "<td>" + std::to_string(r.matches.size()) + "</td>"
            "<td class='path sm'>" + HtmlEsc(r.path) + "</td>"
            "<td>" + szBuf + "</td>"
            "</tr>"
            "<tr class='detail-row'>"
            "<td colspan='7'>"
            "<div class='detail' id='m" + std::to_string(&r - &g_Results[0]) + "' style='display:none'>"
            + matchList +
            "</div></td></tr>\n";
    }

    // Category summary
    std::map<std::string,int> catCount;
    for (auto& r : g_Results)
        for (auto& m : r.matches)
            catCount[m.category]++;

    std::string catRows;
    for (auto& kv : catCount) {
        catRows += "<tr><td><span class='cat-lbl'>" + HtmlEsc(kv.first) +
                   "</span></td><td><b>" + std::to_string(kv.second) + "</b></td></tr>\n";
    }

    std::string H;
    H += "<!DOCTYPE html>\n<html lang='en'><head><meta charset='UTF-8'>";
    H += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
    H += "<title>Dragon String Scanner Report</title>\n<style>\n";
    H += "body{margin:0;background:#050810;color:#c8d8f0;font-family:Segoe UI,sans-serif;font-size:13px}\n";
    H += "body{background-image:linear-gradient(rgba(255,34,68,0.02) 1px,transparent 1px),linear-gradient(90deg,rgba(255,34,68,0.02) 1px,transparent 1px);background-size:40px 40px}\n";
    H += ".header{background:linear-gradient(135deg,#080006,#120010,#080006);border-bottom:3px solid #ff2244;padding:22px 30px}\n";
    H += ".logo{font-size:34px;font-weight:900;color:#ff2244;letter-spacing:5px;text-shadow:0 0 30px rgba(255,34,68,0.8)}\n";
    H += ".sub{font-size:11px;color:#884444;letter-spacing:2px;margin-top:5px}\n";
    H += ".hg{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}\n";
    H += ".meta{text-align:right;font-size:11px;color:#775555;line-height:2}\n";
    H += ".meta b{color:#ff6644}\n";
    H += ".risk{text-align:center;padding:16px;font-size:24px;font-weight:900;letter-spacing:5px;border-bottom:1px solid #1a0510}\n";
    H += ".stats{display:flex;gap:1px;background:#1a0510;border-bottom:1px solid #1a0510}\n";
    H += ".sc{flex:1;padding:14px;background:#080006;text-align:center}\n";
    H += ".sn{font-size:26px;font-weight:900}\n";
    H += ".sl{font-size:10px;letter-spacing:2px;color:#663333;text-transform:uppercase;margin-top:2px}\n";
    H += ".cnt{max-width:1800px;margin:0 auto;padding:16px}\n";
    H += ".sec{background:#080006;border:1px solid #1a0510;border-radius:4px;margin-bottom:14px;overflow:hidden;overflow:clip}\n";
    H += ".sh{display:flex;align-items:center;gap:10px;padding:11px 18px;background:rgba(255,34,68,0.07);border-bottom:1px solid #1a0510}\n";
    H += ".st{font-weight:700;font-size:12px;letter-spacing:1px;color:#ff4444}\n";
    H += ".sb2{margin-left:auto;font-size:11px;color:#663333}\n";
    H += ".sb{padding:0 16px 12px}\n";
    H += "table{width:100%;border-collapse:collapse;font-size:12px}\n";
    H += "th{padding:8px 10px;text-align:left;background:rgba(255,34,68,0.09);color:#ff4444;font-size:10px;letter-spacing:1px;border-bottom:1px solid #1a0510;white-space:nowrap}\n";
    H += "td{padding:7px 10px;border-bottom:1px solid rgba(26,5,16,0.7);vertical-align:top}\n";
    H += "tbody tr:not(.detail-row):hover td{background:rgba(255,34,68,0.05);cursor:pointer}\n";
    H += "tr.cr td{background:rgba(255,34,68,0.1)}\n";
    H += "tr.hi td{background:rgba(255,102,34,0.08)}\n";
    H += "tr:last-child td{border-bottom:none}\n";
    H += ".badge{display:inline-block;padding:2px 8px;border-radius:2px;font-size:10px;font-weight:700;letter-spacing:1px}\n";
    H += ".fn{font-weight:700;color:#ffcccc;min-width:140px}\n";
    H += ".ext-badge{display:inline-block;padding:1px 6px;background:rgba(255,34,68,0.15);border:1px solid rgba(255,34,68,0.3);border-radius:2px;font-size:10px;color:#ff6644;font-weight:700}\n";
    H += ".score{font-size:14px;font-weight:900;color:#ff4444}\n";
    H += ".path{font-size:10px;color:#664444;word-break:break-all}\n";
    H += ".sm{font-size:11px;color:#775555}\n";
    H += ".detail{padding:10px 4px 6px}\n";
    H += ".cat-grp{margin:4px 0;display:flex;flex-wrap:wrap;align-items:center;gap:5px}\n";
    H += ".cat-lbl{display:inline-block;padding:1px 8px;background:rgba(255,34,68,0.15);border:1px solid rgba(255,34,68,0.4);border-radius:2px;font-size:10px;color:#ff6644;font-weight:700;white-space:nowrap}\n";
    H += ".kw{display:inline-block;padding:1px 7px;background:rgba(255,200,0,0.08);border:1px solid rgba(255,200,0,0.25);border-radius:2px;font-size:10px;color:#ffcc88;font-family:Consolas,monospace}\n";
    H += ".ok{text-align:center;padding:20px;color:#44ff88;font-size:13px}\n";
    H += ".foot{text-align:center;padding:18px;font-size:11px;color:#553333;border-top:1px solid #1a0510}\n";
    H += ".foot b{color:#ff4444}\n";
    H += R"CSS(
.tb{position:sticky;top:0;z-index:10;display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:10px 0;background:#080006;border-bottom:1px solid #1a0510}
.tb input,.tb select{background:#0d0410;border:1px solid #3a1020;border-radius:3px;color:#ffdddd;font:12px Segoe UI,sans-serif;padding:7px 10px;outline:none}
.tb input{flex:1;min-width:220px}
.tb input:focus,.tb select:focus{border-color:#ff2244;box-shadow:0 0 0 2px rgba(255,34,68,0.18)}
.tb button{background:rgba(255,34,68,0.12);border:1px solid rgba(255,34,68,0.4);border-radius:3px;color:#ff6644;font:700 11px Segoe UI,sans-serif;letter-spacing:1px;padding:7px 12px;cursor:pointer}
.tb button:hover{background:rgba(255,34,68,0.25)}
.tc{font-size:11px;color:#886666;white-space:nowrap}
)CSS";
    H += "</style></head><body>\n";

    // Header
    H += "<div class='header'><div class='hg'>";
    H += "<div><div class='logo'>&#x1F409; DRAGON STRING SCANNER</div>";
    H += "<div class='sub'>C DRIVE FULL SCAN — EXE / DLL / SYS ANALYSIS</div></div>";
    H += "<div class='meta'>";
    H += "<b>SCAN TIME</b> " + HtmlEsc(g_ScanTime) + "<br>";
    H += "<b>FILES SCANNED</b> " + std::to_string(g_ScannedFiles) + "<br>";
    H += "<b>SUSPICIOUS</b> " + std::to_string(g_SuspiciousFiles) + "<br>";
    H += "<b>TOTAL MATCHES</b> " + std::to_string(g_TotalMatches);
    H += "</div></div></div>\n";

    // Risk
    H += "<div class='risk' style='color:" + riskColor + ";background:" +
         riskColor + "22;border-color:" + riskColor + "'>";
    H += "RISK: " + riskLevel + " &nbsp;|&nbsp; TOTAL SCORE: " + std::to_string(totalScore) +
         " &nbsp;|&nbsp; SUSPICIOUS FILES: " + std::to_string(g_SuspiciousFiles);
    H += "</div>\n";

    // Stats
    H += "<div class='stats'>";
    H += "<div class='sc'><div class='sn' style='color:#ff2244'>" + std::to_string(crit) + "</div><div class='sl'>Critical</div></div>";
    H += "<div class='sc'><div class='sn' style='color:#ff6622'>" + std::to_string(high) + "</div><div class='sl'>High</div></div>";
    H += "<div class='sc'><div class='sn' style='color:#ffcc00'>" + std::to_string(med) + "</div><div class='sl'>Medium</div></div>";
    H += "<div class='sc'><div class='sn' style='color:#88cc44'>" + std::to_string(low) + "</div><div class='sl'>Low</div></div>";
    H += "<div class='sc'><div class='sn' style='color:#ff4444'>" + std::to_string(g_SuspiciousFiles) + "</div><div class='sl'>Files</div></div>";
    H += "<div class='sc'><div class='sn' style='color:#aaa'>" + std::to_string(g_ScannedFiles) + "</div><div class='sl'>Scanned</div></div>";
    H += "</div>\n<div class='cnt'>\n";

    // Category summary
    if (!catRows.empty()) {
        H += "<div class='sec'><div class='sh'><span class='st'>[CAT] DETECTION CATEGORY SUMMARY</span></div>";
        H += "<div class='sb'><table><thead><tr><th>CATEGORY</th><th>MATCHES</th></tr></thead><tbody>";
        H += catRows;
        H += "</tbody></table></div></div>\n";
    }

    // Main results table
    H += "<div class='sec'><div class='sh'><span class='st'>[!] SUSPICIOUS FILES</span>";
    H += "<span class='sb2'>Click row to expand matches</span></div>";
    H += "<div class='sb'>";
    if (fileRows.empty()) {
        H += "<div class='ok'>NO SUSPICIOUS FILES FOUND — SYSTEM APPEARS CLEAN</div>";
    } else {
        H += R"TB(<div class='tb'><input id='q' type='search' placeholder='Search file name, path or keyword...   ( / = focus,  Esc = clear,  -word = exclude )' autocomplete='off' spellcheck='false'><select id='sv'><option value=''>All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select><button id='qx' type='button'>CLEAR</button><span class='tc' id='qc'></span></div>)TB";   // search bar
        H += "<table><thead><tr>";
        H += "<th>SEV</th><th>FILE NAME</th><th>EXT</th>";
        H += "<th>SCORE</th><th>MATCHES</th><th>PATH</th><th>SIZE</th>";
        H += "</tr></thead><tbody>";
        H += fileRows;
        H += "</tbody></table>";
    }
    H += "</div></div>\n";
    H += "</div>\n"; // cnt

    H += "<div class='foot'>&#x1F409; Dragon String Scanner v2.1 &nbsp;|&nbsp; ";
    H += "<b>Scan Time: " + HtmlEsc(g_ScanTime) + "</b> &nbsp;|&nbsp; ";
    H += "Developer: <b>Tasfik Abdullah</b></div>\n";

    H += "<script>\n";
    H += "function tog(id){var e=document.getElementById(id);if(e)e.style.display=e.style.display==='none'?'block':'none';}\n";
    H += R"JS(
(function(){
  var q=document.getElementById('q'), sv=document.getElementById('sv'),
      qx=document.getElementById('qx'), qc=document.getElementById('qc');
  if(!q) return;
  var rows=null, timer=null;
  // "_", "." and "-" count as spaces, so "free panel" finds Free_Panel.dll
  function norm(s){ return s.toLowerCase().replace(/[_.\-]+/g,' '); }
  function build(){
    rows=[];
    var trs=document.querySelectorAll('tr[onclick]');
    for(var i=0;i<trs.length;i++){
      var r=trs[i], d=r.nextElementSibling;
      rows.push({r:r, d:d, sev:r.cells[0].textContent.trim(),
                 t:norm(r.textContent+' '+(d?d.textContent:''))});
    }
  }
  function parse(v){
    var inc=[], exc=[], p=v.trim().split(/\s+/);
    for(var i=0;i<p.length;i++){
      var w=p[i]; if(!w) continue;
      if(w.charAt(0)==='-' && w.length>1) exc.push(norm(w.slice(1)));
      else inc.push(norm(w));
    }
    return {inc:inc, exc:exc};
  }
  function apply(){
    if(!rows) build();
    var f=parse(q.value), s=sv.value, shown=0, i, j, ok, t, o;
    for(i=0;i<rows.length;i++){
      o=rows[i]; t=o.t; ok=(!s || o.sev===s);
      for(j=0;ok && j<f.inc.length;j++) if(t.indexOf(f.inc[j])<0) ok=false;
      for(j=0;ok && j<f.exc.length;j++) if(t.indexOf(f.exc[j])>=0) ok=false;
      o.r.style.display=ok?'':'none';
      if(o.d) o.d.style.display=ok?'':'none';
      if(ok) shown++;
    }
    qc.textContent=(q.value||s) ? ('Showing '+shown+' of '+rows.length+' files') : (rows.length+' files');
  }
  function later(){ clearTimeout(timer); timer=setTimeout(apply,120); }
  q.addEventListener('input',later);
  q.addEventListener('search',apply);
  sv.addEventListener('change',apply);
  qx.addEventListener('click',function(){ q.value=''; sv.value=''; apply(); q.focus(); });
  document.addEventListener('keydown',function(e){
    var a=document.activeElement;
    if(e.key==='/' && a!==q && a!==sv){ e.preventDefault(); q.focus(); q.select(); }
    else if(e.key==='Escape' && a===q){ q.value=''; apply(); }
  });
  qc.textContent=document.querySelectorAll('tr[onclick]').length+' files';
})();
)JS";
    H += "</script>\n";
    H += "</body></html>";

    HANDLE hOut = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut != INVALID_HANDLE_VALUE) {
        size_t off = 0;
        while (off < H.size()) {
            DWORD chunk = (DWORD)std::min<size_t>(H.size() - off, 1u << 24), wr = 0;
            if (!WriteFile(hOut, H.data() + off, chunk, &wr, nullptr) || wr == 0) break;
            off += wr;
        }
        CloseHandle(hOut);
    }
}

// ============================================================
//  BANNER
// ============================================================
void ShowBanner() {
    g_hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleA("Dragon String Scanner v2.1 | Tasfik Abdullah");

    SMALL_RECT wr={0,0,99,39};
    SetConsoleWindowInfo(g_hCon,TRUE,&wr);
    COORD bs={100,40}; SetConsoleScreenBufferSize(g_hCon,bs);

    CONSOLE_CURSOR_INFO ci={1,FALSE}; SetConsoleCursorInfo(g_hCon,&ci);

    static const char* art[]={
        "    ███████╗████████╗██████╗ ██╗███╗  ██╗ ██████╗ ",
        "    ██╔════╝╚══██╔══╝██╔══██╗██║████╗ ██║██╔════╝ ",
        "    ███████╗   ██║   ██████╔╝██║██╔██╗██║██║  ███╗",
        "    ╚════██║   ██║   ██╔══██╗██║██║╚████║██║   ██║",
        "    ███████║   ██║   ██║  ██║██║██║ ╚███║╚██████╔╝",
        "    ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚══╝ ╚═════╝ ",
        "                  S C A N N E R   v 2 . 1          ",
    };
    WORD cols[]={COL_RED_B,COL_RED_B,COL_RED_B,COL_RED_B,COL_RED_B,COL_RED_B,COL_YELLOW_B};
    std::cout << "\n";
    for(int i=0;i<7;i++){SetCol(cols[i]);std::cout<<art[i]<<"\n";Sleep(25);}
    std::cout<<"\n";

    SetCol(COL_RED);
    std::cout<<"  "; for(int i=0;i<88;i++)std::cout<<"\xE2\x95\x90";
    std::cout<<"\n";
    SetCol(COL_WHITE_B);
    std::cout<<"  Developer : Tasfik Abdullah\n";
    std::cout<<"  Scan      : C:\\ - EXE, DLL, SYS - String Analysis\n";
    std::cout<<"  Report    : Desktop\\DragonStringScan_<timestamp>.html\n";
    SetCol(COL_RED);
    std::cout<<"  "; for(int i=0;i<88;i++)std::cout<<"\xE2\x95\x90";
    std::cout<<"\n\n"; SetCol(COL_DEFAULT);

    CONSOLE_CURSOR_INFO ci2={1,TRUE}; SetConsoleCursorInfo(g_hCon,&ci2);
}

// ============================================================
//  MAIN
// ============================================================
int main() {
    ShowBanner();

    // ── License key gate (checks + consumes a one-time key from GitHub)
    if (!RunKeyGate()) {
        SetCol(COL_DEFAULT);
        std::cout << "\n  Exiting.\n";
        system("pause > nul");
        return 1;
    }

    // ── Arguments (wide, so non-English folder names work)
    int argcW = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
    std::wstring root = L"C:";
    int nThreads = 0;
    if (argvW) {
        for (int i = 1; i < argcW; i++) {
            std::wstring a = argvW[i];
            if (a == L"--fast" || a == L"-f") g_FastMode = true;
            else if ((a == L"--threads" || a == L"-t") && i + 1 < argcW) nThreads = _wtoi(argvW[++i]);
            else root = a;
        }
        LocalFree(argvW);
    }
    while (root.size() > 2 && (root.back() == L'\\' || root.back() == L'/')) root.pop_back();

    std::wstring probe = root;
    if (probe.size() == 2 && probe[1] == L':') probe += L"\\";
    DWORD attr = GetFileAttributesW(probe.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        SetCol(COL_RED_B);
        std::cout << "  [ERROR] Folder not found: " << WideToUtf8(root) << "\n\n";
        SetCol(COL_DEFAULT);
        system("pause > nul");
        return 1;
    }

    // ── Thread count
    SYSTEM_INFO si; GetSystemInfo(&si);
    if (nThreads <= 0) {
        nThreads = (int)si.dwNumberOfProcessors;
        if (nThreads < 2)  nThreads = 2;
        if (nThreads > 16) nThreads = 16;
    }
    if (nThreads > 64) nThreads = 64;

    // ── Output path + timestamp
    wchar_t desktop[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, 0, desktop)) || !desktop[0])
        wcscpy(desktop, L".");
    SYSTEMTIME st; GetLocalTime(&st);
    char tsBuf[32], tmBuf[32];
    snprintf(tsBuf, sizeof(tsBuf), "%04d%02d%02d_%02d%02d%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    snprintf(tmBuf, sizeof(tmBuf), "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    g_ScanTime = tmBuf;
    std::wstring outPath = std::wstring(desktop) + L"\\DragonStringScan_" +
                           std::wstring(tsBuf, tsBuf + strlen(tsBuf)) + L".html";

    // ── Build keyword automaton
    BuildKeywordTable();
    InitSkipList();
    LoadBadHashes();
    {
        std::vector<std::string> texts; std::vector<bool> wide;
        for (auto& k : g_Keywords) { texts.push_back(k.text); wide.push_back(k.wide); }
        g_Matcher.Build(texts, wide);
    }

    SetCol(COL_YELLOW_B);
    std::cout << "  [*] Starting scan: " << WideToUtf8(root) << "\\\n";
    std::cout << "  [*] Extensions  : .exe .dll .sys\n";
    std::cout << "  [*] Keywords    : " << g_Keywords.size() << " unique\n";
    std::cout << "  [*] Hash list   : " << g_BadHashes.size() << " known-bad (add more in hashes.txt next to the exe)\n";
    std::cout << "  [*] Threads     : " << nThreads << (g_FastMode ? "   (--fast: C:\\Windows skipped)" : "") << "\n";
    std::cout << "  [*] Report      : " << WideToUtf8(outPath) << "\n\n";
    SetCol(COL_DEFAULT);

    // ── Start workers
    InitializeCriticalSection(&g_QCS);
    InitializeCriticalSection(&g_ResultsCS);
    InitializeConditionVariable(&g_QCV);
    std::vector<HANDLE> workers;
    for (int i = 0; i < nThreads; i++) {
        HANDLE t = CreateThread(nullptr, 0, WorkerProc, nullptr, 0, nullptr);
        if (t) workers.push_back(t);
    }
    if (workers.empty()) {
        SetCol(COL_RED_B);
        std::cout << "  [ERROR] Could not start worker threads.\n";
        SetCol(COL_DEFAULT);
        return 1;
    }

    // ── Scan: main thread enumerates, workers read + match
    auto startTime = std::chrono::steady_clock::now();
    ScanDirectory(root, 0);
    EnterCriticalSection(&g_QCS);
    g_EnumDone = true;
    LeaveCriticalSection(&g_QCS);
    WakeAllConditionVariable(&g_QCV);
    while (WaitForMultipleObjects((DWORD)workers.size(), workers.data(), TRUE, 100) == WAIT_TIMEOUT)
        Progress(false);
    for (HANDLE t : workers) CloseHandle(t);
    auto elapsed = std::chrono::steady_clock::now() - startTime;
    double sec = std::chrono::duration<double>(elapsed).count();

    g_ScannedFiles    = (int)c_Done;
    g_SkippedFiles    = (int)c_SkippedFiles;
    g_SuspiciousFiles = (int)g_Results.size();
    g_TotalMatches    = 0;
    for (auto& r : g_Results) g_TotalMatches += (int)r.matches.size();

    std::cout << "\n\n";
    SetCol(COL_RED);
    std::cout << "  "; for (int i = 0; i < 88; i++) std::cout << "\xE2\x95\x90";
    std::cout << "\n";
    SetCol(COL_RED_B); std::cout << "    SCAN COMPLETE\n";
    SetCol(COL_RED);
    std::cout << "  "; for (int i = 0; i < 88; i++) std::cout << "\xE2\x95\x90";
    std::cout << "\n";
    SetCol(COL_WHITE_B);
    char secBuf[32]; snprintf(secBuf, sizeof(secBuf), "%.1f", sec);
    char spdBuf[32]; snprintf(spdBuf, sizeof(spdBuf), "%.0f", sec > 0 ? ((double)c_Bytes / (1024.0 * 1024.0)) / sec : 0.0);
    std::cout << "  Files Scanned   : " << g_ScannedFiles << "\n";
    std::cout << "  Folders Skipped : " << (int)c_SkippedDirs << "\n";
    std::cout << "  Files Skipped   : " << (int)(g_SkippedFiles + c_Unreadable) << "  (empty / >100MB / locked / cloud-only)\n";
    std::cout << "  Suspicious Files: " << g_SuspiciousFiles << "\n";
    std::cout << "  API-only (hidden): " << (int)c_ApiOnly << "  (only generic Windows API names, not reported)\n";
    std::cout << "  Total Matches   : " << g_TotalMatches << "\n";
    std::cout << "  Scan Time       : " << secBuf << " seconds  (" << spdBuf << " MB/s, "
              << workers.size() << " threads)\n";
    SetCol(COL_RED);
    std::cout << "  "; for (int i = 0; i < 88; i++) std::cout << "\xE2\x95\x90";
    std::cout << "\n\n";

    // ── Report
    SetCol(COL_CYAN_B);
    std::cout << "  [*] Generating HTML report...\n";
    GenerateReport(outPath);
    SetCol(COL_GREEN_B);
    std::cout << "  [+] Report saved: " << WideToUtf8(outPath) << "\n\n";
    SetCol(COL_DEFAULT);

    // Auto-open
    ShellExecuteW(nullptr, L"open", outPath.c_str(), nullptr, nullptr, SW_SHOW);

    std::cout << "  Press any key to exit...\n";
    system("pause > nul");
    return 0;
}
