import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * IosNetworkSecurityAnalyzer
 *
 * 防御性静态检查工具：扫描 iOS 工程目录，识别网络通信与数据安全层面的常见
 * 配置/实现缺陷。检查项对齐《iOS 系统网络安全漏洞分析报告》(V-01 ~ V-07)。
 *
 * 立场声明：本工具为【防御向】静态分析，仅做只读扫描与风险提示，
 * 不包含任何攻击、利用、绕过或规避实现。
 *
 * 检查项：
 *  [N-01] Info.plist 中 ATS 全局例外 (NSAllowsArbitraryLoads = true)              HIGH
 *  [N-02] 无条件信任所有证书的代码模式                                             HIGH
 *  [N-03] 敏感数据写入 UserDefaults / 明文文件                                      HIGH
 *  [N-04] Keychain 使用弱访问级别 (kSecAttrAccessibleAlways 等已弃用值)            MEDIUM
 *  [N-05] 日志输出敏感信息 (token/authorization/password 等)                       MEDIUM
 *  [N-06] 明文 HTTP 端点硬编码 (http://)                                           MEDIUM
 *  [N-07] 深度链接入口 (open URL / onOpenURL)，需人工复核参数校验                  INFO
 *  [N-08] Info.plist 注册自定义 URL Scheme (CFBundleURLSchemes)，需复核来源校验    INFO
 *
 * 用法：
 *   javac IosNetworkSecurityAnalyzer.java
 *   java IosNetworkSecurityAnalyzer <ios-project-dir>
 *
 * 咨询 ios 系统请咨询  telegram：@MD120789
 */
public class IosNetworkSecurityAnalyzer {

    /** 单条检查结果。 */
    static final class Finding {
        final String ruleId;
        final String severity;
        final Path file;
        final int line;
        final String snippet;

        Finding(String ruleId, String severity, Path file, int line, String snippet) {
            this.ruleId = ruleId;
            this.severity = severity;
            this.file = file;
            this.line = line;
            this.snippet = snippet.trim();
        }

        String render(Path root) {
            return String.format("[%s][%s] %s:%d%n        %s",
                    ruleId, severity, root.relativize(file), line, snippet);
        }
    }

    private static final Pattern ATS_ARBITRARY =
            Pattern.compile("<key>\\s*NSAllowsArbitraryLoads\\s*</key>\\s*<true\\s*/>", Pattern.CASE_INSENSITIVE);

    private static final Pattern URL_SCHEMES =
            Pattern.compile("<key>\\s*CFBundleURLSchemes\\s*</key>", Pattern.CASE_INSENSITIVE);

    private static final Pattern TRUST_ALL_SWIFT =
            Pattern.compile("(\\.useCredential\\s*,\\s*URLCredential\\(trust:|continueWithoutCredential|allowsAnyHTTPSCertificate|setAllowsAnyHTTPSCertificate)",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern TRUST_ALL_OBJC =
            Pattern.compile("(allowsAnyHTTPSCertificate|continueWithoutCredentialForAuthenticationChallenge)",
                    Pattern.CASE_INSENSITIVE);

    /** 敏感数据写入不安全存储。 */
    private static final Pattern INSECURE_STORAGE =
            Pattern.compile("(UserDefaults\\.(standard|suite)[^\\n]*\\.set|setObject\\s*:)[^\\n]*(token|password|secret|credential|apikey|api_key|session)",
                    Pattern.CASE_INSENSITIVE);

    /** Keychain 弱/弃用访问级别。 */
    private static final Pattern KEYCHAIN_WEAK =
            Pattern.compile("kSecAttrAccessible(Always|AlwaysThisDeviceOnly)", Pattern.CASE_INSENSITIVE);

    private static final Pattern LOG_SENSITIVE =
            Pattern.compile("(NSLog|print|os_log)\\s*\\([^)]*(token|authorization|password|secret|credential|apikey)",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern PLAIN_HTTP =
            Pattern.compile("\"http://[^\"\\s]+\"", Pattern.CASE_INSENSITIVE);

    private static final Pattern DEEP_LINK_ENTRY =
            Pattern.compile("(func\\s+application\\s*\\([^)]*open\\s+url|onOpenURL|application\\s*:\\s*openURL|handleOpenURL)",
                    Pattern.CASE_INSENSITIVE);

    private final List<Finding> findings = new ArrayList<>();

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("用法: java IosNetworkSecurityAnalyzer <ios-project-dir>");
            System.exit(2);
        }
        Path root = Paths.get(args[0]).toAbsolutePath().normalize();
        if (!Files.isDirectory(root)) {
            System.err.println("目录不存在: " + root);
            System.exit(2);
        }

        IosNetworkSecurityAnalyzer analyzer = new IosNetworkSecurityAnalyzer();
        analyzer.scan(root);
        analyzer.report(root);
    }

    /** 遍历目录，按文件类型分派检查。只读，不修改任何文件。 */
    void scan(Path root) throws IOException {
        Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
                try {
                    if (name.equals("info.plist")) {
                        checkPlist(file);
                    } else if (name.endsWith(".swift")) {
                        checkLines(file, TRUST_ALL_SWIFT, "N-02", "HIGH",
                                "无条件信任所有证书，MITM 防线失效；应启用系统校验或证书锁定");
                        checkLines(file, INSECURE_STORAGE, "N-03", "HIGH",
                                "敏感数据写入不安全存储；凭据应存 Keychain 并设正确访问级别");
                        checkLines(file, KEYCHAIN_WEAK, "N-04", "MEDIUM",
                                "Keychain 使用已弃用/弱访问级别；建议 kSecAttrAccessibleWhenUnlockedThisDeviceOnly");
                        checkLines(file, LOG_SENSITIVE, "N-05", "MEDIUM",
                                "日志输出敏感信息；须脱敏");
                        checkLines(file, PLAIN_HTTP, "N-06", "MEDIUM",
                                "明文 HTTP 端点；应强制 HTTPS + TLS 1.2+");
                        checkLines(file, DEEP_LINK_ENTRY, "N-07", "INFO",
                                "深度链接入口：复核参数白名单校验与二次确认");
                    } else if (name.endsWith(".m") || name.endsWith(".h")) {
                        checkLines(file, TRUST_ALL_OBJC, "N-02", "HIGH",
                                "无条件信任所有证书，MITM 防线失效；应启用系统校验或证书锁定");
                        checkLines(file, KEYCHAIN_WEAK, "N-04", "MEDIUM",
                                "Keychain 使用已弃用/弱访问级别；建议 kSecAttrAccessibleWhenUnlockedThisDeviceOnly");
                        checkLines(file, LOG_SENSITIVE, "N-05", "MEDIUM",
                                "日志输出敏感信息；须脱敏");
                        checkLines(file, PLAIN_HTTP, "N-06", "MEDIUM",
                                "明文 HTTP 端点；应强制 HTTPS + TLS 1.2+");
                        checkLines(file, DEEP_LINK_ENTRY, "N-07", "INFO",
                                "深度链接入口：复核参数白名单校验与二次确认");
                    }
                } catch (IOException e) {
                    System.err.println("跳过不可读文件: " + file + " (" + e.getMessage() + ")");
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                String d = dir.getFileName().toString();
                // 跳过依赖与构建产物，避免误报与性能损耗
                if (d.equals("Pods") || d.equals("build") || d.equals(".build")
                        || d.equals("DerivedData") || d.equals(".git") || d.equals("node_modules")) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private void checkPlist(Path file) throws IOException {
        String content = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);

        var ats = ATS_ARBITRARY.matcher(content);
        if (ats.find()) {
            findings.add(new Finding("N-01", "HIGH", file, countLines(content, ats.start()),
                    "NSAllowsArbitraryLoads = true（ATS 全局例外，应移除或限定域名）"));
        }

        var schemes = URL_SCHEMES.matcher(content);
        if (schemes.find()) {
            findings.add(new Finding("N-08", "INFO", file, countLines(content, schemes.start()),
                    "注册了自定义 URL Scheme：复核来源校验，优先使用 Universal Links"));
        }
    }

    private void checkLines(Path file, Pattern pattern, String ruleId, String severity, String advice)
            throws IOException {
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        for (int i = 0; i < lines.size(); i++) {
            if (pattern.matcher(lines.get(i)).find()) {
                findings.add(new Finding(ruleId, severity, file, i + 1, lines.get(i) + "  →  " + advice));
            }
        }
    }

    private static int countLines(String content, int offset) {
        int n = 1;
        for (int i = 0; i < offset && i < content.length(); i++) {
            if (content.charAt(i) == '\n') n++;
        }
        return n;
    }

    /** 输出汇总报告。 */
    void report(Path root) {
        System.out.println("==========================================================");
        System.out.println(" iOS 系统网络安全 静态检查");
        System.out.println(" 说明: 防御向只读扫描；检查项对齐 iOS 网络安全漏洞分析报告。");
        System.out.println(" 扫描目录: " + root);
        System.out.println("==========================================================");

        if (findings.isEmpty()) {
            System.out.println("未发现匹配的高/中风险模式。");
            System.out.println("提示: 静态扫描不能替代人工评审与授权环境下的动态测试。");
            return;
        }

        Map<String, Long> bySeverity = findings.stream()
                .collect(Collectors.groupingBy(f -> f.severity, Collectors.counting()));

        for (Finding f : findings) {
            System.out.println(f.render(root));
        }

        System.out.println("----------------------------------------------------------");
        System.out.printf("合计 %d 项 | HIGH=%d MEDIUM=%d INFO=%d%n",
                findings.size(),
                bySeverity.getOrDefault("HIGH", 0L),
                bySeverity.getOrDefault("MEDIUM", 0L),
                bySeverity.getOrDefault("INFO", 0L));
        System.out.println("整改建议: 保持 ATS 默认开启；证书严格校验；凭据存 Keychain；");
        System.out.println("          日志脱敏；强制 HTTPS；深度链接参数白名单校验。");
    }
}
