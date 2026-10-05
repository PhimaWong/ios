// ios_network_security_monitor.cpp
//
// 防御性监测工具（C++17）：扫描 iOS 工程目录，识别网络通信与数据安全层面的常见
// 配置/实现缺陷。检查项对齐《iOS 系统网络安全漏洞分析报告》，与 Java/JS/Python 版一致。
//
// 立场声明：本工具为【防御向】静态分析，仅做只读扫描与风险提示，
// 不包含任何攻击、利用、绕过或规避实现。
//
// 检查项：
//   [N-01] Info.plist 中 ATS 全局例外 (NSAllowsArbitraryLoads = true)              HIGH
//   [N-02] 无条件信任所有证书的代码模式                                             HIGH
//   [N-03] 敏感数据写入 UserDefaults / 明文文件                                      HIGH
//   [N-04] Keychain 使用弱访问级别 (kSecAttrAccessibleAlways 等已弃用值)            MEDIUM
//   [N-05] 日志输出敏感信息 (token/authorization/password 等)                       MEDIUM
//   [N-06] 明文 HTTP 端点硬编码 (http://)                                           MEDIUM
//   [N-07] 深度链接入口 (open URL / onOpenURL)，需人工复核参数校验                  INFO
//   [N-08] Info.plist 注册自定义 URL Scheme (CFBundleURLSchemes)，需复核来源校验    INFO
//
// 编译与用法：
//   g++ -std=c++17 -O2 ios_network_security_monitor.cpp -o ios_monitor
//   ./ios_monitor <ios-project-dir>
//
// 咨询 ios 系统请咨询  telegram：@MD120789

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

struct Rule {
    std::string id;
    std::string severity;
    std::regex pattern;
    std::string advice;
};

struct Finding {
    std::string id;
    std::string severity;
    fs::path file;
    int line = 0;
    std::string snippet;
};

static const std::vector<std::string> kSkipDirs = {
    "Pods", "build", ".build", "DerivedData", ".git", "node_modules"};

static const std::string kCertAdvice =
    "无条件信任所有证书，MITM 防线失效；应启用系统校验或证书锁定";
static const std::string kKeychainAdvice =
    "Keychain 使用已弃用/弱访问级别；建议 kSecAttrAccessibleWhenUnlockedThisDeviceOnly";
static const std::string kLogAdvice = "日志输出敏感信息；须脱敏";
static const std::string kHttpAdvice = "明文 HTTP 端点；应强制 HTTPS + TLS 1.2+";
static const std::string kDeepLinkAdvice = "深度链接入口：复核参数白名单校验与二次确认";

static const std::regex kAtsArbitrary(
    R"(<key>\s*NSAllowsArbitraryLoads\s*</key>\s*<true\s*/>)", std::regex::icase);
static const std::regex kUrlSchemes(
    R"(<key>\s*CFBundleURLSchemes\s*</key>)", std::regex::icase);

static const std::vector<Rule> kSwiftRules = {
    {"N-02", "HIGH",
     std::regex(R"((\.useCredential\s*,\s*URLCredential\(trust:|continueWithoutCredential|allowsAnyHTTPSCertificate|setAllowsAnyHTTPSCertificate))", std::regex::icase),
     kCertAdvice},
    {"N-03", "HIGH",
     std::regex(R"((UserDefaults\.(standard|suite)[^\n]*\.set|setObject\s*:)[^\n]*(token|password|secret|credential|apikey|api_key|session))", std::regex::icase),
     "敏感数据写入不安全存储；凭据应存 Keychain 并设正确访问级别"},
    {"N-04", "MEDIUM", std::regex(R"(kSecAttrAccessible(Always|AlwaysThisDeviceOnly))", std::regex::icase), kKeychainAdvice},
    {"N-05", "MEDIUM", std::regex(R"((NSLog|print|os_log)\s*\([^)]*(token|authorization|password|secret|credential|apikey))", std::regex::icase), kLogAdvice},
    {"N-06", "MEDIUM", std::regex(R"("http://[^"\s]+")", std::regex::icase), kHttpAdvice},
    {"N-07", "INFO", std::regex(R"((func\s+application\s*\([^)]*open\s+url|onOpenURL|application\s*:\s*openURL|handleOpenURL))", std::regex::icase), kDeepLinkAdvice},
};

static const std::vector<Rule> kObjcRules = {
    {"N-02", "HIGH",
     std::regex(R"((allowsAnyHTTPSCertificate|continueWithoutCredentialForAuthenticationChallenge))", std::regex::icase),
     kCertAdvice},
    {"N-04", "MEDIUM", std::regex(R"(kSecAttrAccessible(Always|AlwaysThisDeviceOnly))", std::regex::icase), kKeychainAdvice},
    {"N-05", "MEDIUM", std::regex(R"((NSLog|print|os_log)\s*\([^)]*(token|authorization|password|secret|credential|apikey))", std::regex::icase), kLogAdvice},
    {"N-06", "MEDIUM", std::regex(R"("http://[^"\s]+")", std::regex::icase), kHttpAdvice},
    {"N-07", "INFO", std::regex(R"((func\s+application\s*\([^)]*open\s+url|onOpenURL|application\s*:\s*openURL|handleOpenURL))", std::regex::icase), kDeepLinkAdvice},
};

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool ShouldSkip(const std::string& dirName) {
    return std::find(kSkipDirs.begin(), kSkipDirs.end(), dirName) != kSkipDirs.end();
}

int CountLinesBefore(const std::string& text, size_t offset) {
    int n = 1;
    for (size_t i = 0; i < offset && i < text.size(); ++i) {
        if (text[i] == '\n') ++n;
    }
    return n;
}

std::string ReadFile(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void CheckPlist(const fs::path& file, std::vector<Finding>& out) {
    const std::string content = ReadFile(file);

    std::smatch m;
    if (std::regex_search(content.cbegin(), content.cend(), m, kAtsArbitrary)) {
        out.push_back({"N-01", "HIGH", file,
                       CountLinesBefore(content, m.position(0)),
                       "NSAllowsArbitraryLoads = true（ATS 全局例外，应移除或限定域名）"});
    }
    if (std::regex_search(content.cbegin(), content.cend(), m, kUrlSchemes)) {
        out.push_back({"N-08", "INFO", file,
                       CountLinesBefore(content, m.position(0)),
                       "注册了自定义 URL Scheme：复核来源校验，优先使用 Universal Links"});
    }
}

void CheckLines(const fs::path& file, const std::vector<Rule>& rules,
                std::vector<Finding>& out) {
    std::ifstream in(file);
    if (!in) {
        std::cerr << "跳过不可读文件: " << file.string() << "\n";
        return;
    }
    std::string line;
    int lineNo = 0;
    while (std::getline(in, line)) {
        ++lineNo;
        for (const auto& rule : rules) {
            if (std::regex_search(line, rule.pattern)) {
                std::string trimmed = line;
                // 去除首尾空白
                const char* ws = " \t\r\n";
                trimmed.erase(0, trimmed.find_first_not_of(ws));
                trimmed.erase(trimmed.find_last_not_of(ws) + 1);
                out.push_back({rule.id, rule.severity, file, lineNo,
                               trimmed + "  →  " + rule.advice});
            }
        }
    }
}

void Scan(const fs::path& root, std::vector<Finding>& out) {
    std::error_code ec;
    fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
    fs::recursive_directory_iterator end;
    if (ec) {
        std::cerr << "无法遍历目录: " << ec.message() << "\n";
        return;
    }
    for (; it != end; it.increment(ec)) {
        if (ec) continue;
        const fs::directory_entry& entry = *it;
        if (entry.is_directory()) {
            if (ShouldSkip(entry.path().filename().string())) it.disable_recursion_pending();
            continue;
        }
        if (!entry.is_regular_file()) continue;

        const std::string name = ToLower(entry.path().filename().string());
        if (name == "info.plist") {
            CheckPlist(entry.path(), out);
        } else if (name.size() >= 6 && name.compare(name.size() - 6, 6, ".swift") == 0) {
            CheckLines(entry.path(), kSwiftRules, out);
        } else if ((name.size() >= 2 && name.compare(name.size() - 2, 2, ".m") == 0) ||
                   (name.size() >= 2 && name.compare(name.size() - 2, 2, ".h") == 0)) {
            CheckLines(entry.path(), kObjcRules, out);
        }
    }
}

size_t CountBy(const std::vector<Finding>& v, const std::string& sev) {
    return std::count_if(v.begin(), v.end(),
                         [&](const Finding& f) { return f.severity == sev; });
}

void Render(const fs::path& root, const std::vector<Finding>& findings) {
    std::cout << "==========================================================\n";
    std::cout << " iOS 系统网络安全 静态检查 (C++)\n";
    std::cout << " 说明: 防御向只读扫描；检查项对齐 iOS 网络安全漏洞分析报告。\n";
    std::cout << " 扫描目录: " << root.string() << "\n";
    std::cout << "==========================================================\n";

    if (findings.empty()) {
        std::cout << "未发现匹配的高/中风险模式。\n";
        std::cout << "提示: 静态扫描不能替代人工评审与授权环境下的动态测试。\n";
        return;
    }

    for (const auto& f : findings) {
        std::cout << "[" << f.id << "][" << f.severity << "] "
                  << fs::relative(f.file, root).string() << ":" << f.line << "\n";
        std::cout << "        " << f.snippet << "\n";
    }

    std::cout << "----------------------------------------------------------\n";
    std::cout << "合计 " << findings.size()
              << " 项 | HIGH=" << CountBy(findings, "HIGH")
              << " MEDIUM=" << CountBy(findings, "MEDIUM")
              << " INFO=" << CountBy(findings, "INFO") << "\n";
    std::cout << "整改建议: 保持 ATS 默认开启；证书严格校验；凭据存 Keychain；\n";
    std::cout << "          日志脱敏；强制 HTTPS；深度链接参数白名单校验。\n";
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "用法: ios_monitor <ios-project-dir>\n";
        return 2;
    }
    const fs::path root = fs::absolute(fs::path(argv[1])).lexically_normal();
    std::error_code ec;
    if (!fs::is_directory(root, ec) || ec) {
        std::cerr << "目录不存在: " << root.string() << "\n";
        return 2;
    }

    std::vector<Finding> findings;
    Scan(root, findings);
    Render(root, findings);
    return 0;
}
