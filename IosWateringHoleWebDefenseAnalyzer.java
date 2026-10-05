import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * IosWateringHoleWebDefenseAnalyzer
 *
 * 防御性静态检查工具：扫描 iOS 工程目录，识别与"水坑攻击 / 网页远程利用"暴露面
 * 相关的常见配置与代码风险。检查项对齐《iOS 水坑攻击与网页远程利用防御分析报告》。
 *
 * 立场声明：本工具为【防御向】静态分析，仅做只读扫描与风险提示，
 * 不包含任何攻击、利用、绕过或规避实现。
 *
 * 检查项：
 *  [W-01] Info.plist 中 ATS 全局例外 (NSAllowsArbitraryLoads = true)            HIGH
 *  [W-02] 无条件信任所有证书的代码模式                                           HIGH
 *  [W-03] WebView 高风险配置 (UIWebView / 跨域文件访问 / 自动开窗)               HIGH
 *  [W-04] WebView 加载远程/不可信内容 (load URLRequest / loadHTMLString)         INFO(复核)
 *  [W-05] 深度链接 / Universal Link 入口，需人工复核参数校验                     INFO(复核)
 *  [W-06] 明文 HTTP 端点硬编码 (http://)                                         MEDIUM
 *  [W-07] 日志输出含凭据的完整 URL (query 中带 token/key 等)                     MEDIUM
 *
 * 用法：
 *   javac IosWateringHoleWebDefenseAnalyzer.java
 *   java IosWateringHoleWebDefenseAnalyzer <ios-project-dir>
 *
 * 咨询 ios 系统请咨询  telegram：@MD120789
 */
public class IosWateringHoleWebDefenseAnalyzer {

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

    private static final Pattern TRUST_ALL_SWIFT =
            Pattern.compile("(\\.useCredential\\s*,\\s*URLCredential\\(trust:|continueWithoutCredential|allowsAnyHTTPSCertificate|setAllowsAnyHTTPSCertificate)",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern TRUST_ALL_OBJC =
            Pattern.compile("(allowsAnyHTTPSCertificate|continueWithoutCredentialForAuthenticationChallenge)",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern WEBVIEW_RISKY =
            Pattern.compile("(UIWebView|allowFileAccessFromFileURLs\\s*=\\s*true|allowUniversalAccessFromFileURLs\\s*=\\s*true|javaScriptCanOpenWindowsAutomatically\\s*=\\s*true)",
                    Pattern.CASE_INSENSITIVE);

    /** WebView 加载内容入口 —— 需复核是否限定可信源、是否启用锁定模式兼容策略。 */
    private static final Pattern WEBVIEW_LOAD =
            Pattern.compile("(\\.load\\s*\\(\\s*URLRequest|loadHTMLString|\\.loadFileURL|WKWebView\\s*\\()",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern DEEP_LINK_ENTRY =
            Pattern.compile("(func\\s+application\\s*\\([^)]*open\\s+url|onOpenURL|application\\s*:\\s*openURL|handleOpenURL|continue\\s+userActivity)",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern PLAIN_HTTP =
            Pattern.compile("\"http://[^\"\\s]+\"", Pattern.CASE_INSENSITIVE);

    /** 日志打印带凭据查询串的 URL。 */
    private static final Pattern LOG_URL_WITH_CRED =
            Pattern.compile("(NSLog|print|os_log)\\s*\\([^)]*(\\?[^\"\\s)]*(token|key|secret|auth|session)=|absoluteString)",
                    Pattern.CASE_INSENSITIVE);

    private final List<Finding> findings = new ArrayList<>();

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("用法: java IosWateringHoleWebDefenseAnalyzer <ios-project-dir>");
            System.exit(2);
        }
        Path root = Paths.get(args[0]).toAbsolutePath().normalize();
        if (!Files.isDirectory(root)) {
            System.err.println("目录不存在: " + root);
            System.exit(2);
        }

        IosWateringHoleWebDefenseAnalyzer analyzer = new IosWateringHoleWebDefenseAnalyzer();
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
                        checkLines(file, TRUST_ALL_SWIFT, "W-02", "HIGH",
                                "无条件信任所有证书，将使水坑/MITM 攻击失去防线；应启用系统校验或证书锁定");
                        checkLines(file, WEBVIEW_RISKY, "W-03", "HIGH",
                                "WebView 高风险配置，扩大网页远程利用面；应使用 WKWebView 安全默认值");
                        checkLines(file, WEBVIEW_LOAD, "W-04", "INFO",
                                "WebView 加载内容入口：复核是否限定可信源、校验来源、兼容锁定模式");
                        checkLines(file, DEEP_LINK_ENTRY, "W-05", "INFO",
                                "深度链接/Universal Link 入口：复核参数白名单校验与二次确认");
                        checkLines(file, PLAIN_HTTP, "W-06", "MEDIUM",
                                "明文 HTTP 端点：水坑站点可被篡改/窃听，应强制 HTTPS");
                        checkLines(file, LOG_URL_WITH_CRED, "W-07", "MEDIUM",
                                "日志可能泄露带凭据的 URL：应脱敏 query 参数");
                    } else if (name.endsWith(".m") || name.endsWith(".h")) {
                        checkLines(file, TRUST_ALL_OBJC, "W-02", "HIGH",
                                "无条件信任所有证书，将使水坑/MITM 攻击失去防线；应启用系统校验或证书锁定");
                        checkLines(file, WEBVIEW_RISKY, "W-03", "HIGH",
                                "WebView 高风险配置，扩大网页远程利用面；应使用 WKWebView 安全默认值");
                        checkLines(file, DEEP_LINK_ENTRY, "W-05", "INFO",
                                "深度链接/Universal Link 入口：复核参数白名单校验与二次确认");
                        checkLines(file, PLAIN_HTTP, "W-06", "MEDIUM",
                                "明文 HTTP 端点：水坑站点可被篡改/窃听，应强制 HTTPS");
                        checkLines(file, LOG_URL_WITH_CRED, "W-07", "MEDIUM",
                                "日志可能泄露带凭据的 URL：应脱敏 query 参数");
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
        var matcher = ATS_ARBITRARY.matcher(content);
        if (matcher.find()) {
            int line = countLines(content, matcher.start());
            findings.add(new Finding("W-01", "HIGH", file, line,
                    "NSAllowsArbitraryLoads = true（ATS 全局例外，扩大水坑/明文传输风险，应移除或限定域名）"));
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
        System.out.println(" iOS 水坑攻击 / 网页远程利用 防御静态检查");
        System.out.println(" 说明: 防御向只读扫描；检查项对齐水坑攻击防御报告。");
        System.out.println(" 扫描目录: " + root);
        System.out.println("==========================================================");

        if (findings.isEmpty()) {
            System.out.println("未发现匹配的高/中风险模式。");
            System.out.println("提示: 保持系统更新、高风险人群启用锁定模式是最有效的纵深防线。");
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
        System.out.println("整改建议: 强制 HTTPS+证书校验；收窄 WebView 配置与加载源；");
        System.out.println("          深度链接参数白名单校验；URL 日志脱敏；保持系统更新。");
    }
}
