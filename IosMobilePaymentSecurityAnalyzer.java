import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * IosMobilePaymentSecurityAnalyzer
 *
 * 防御性静态检查工具：扫描 iOS 工程目录，识别移动支付链路（Apple Pay / IAP /
 * 自建支付通道）中常见的实现与配置风险。检查项对齐《iOS 移动支付安全漏洞分析报告》。
 *
 * 立场声明：本工具为【防御向】静态分析，仅做只读扫描与风险提示，
 * 不包含任何攻击、绕过、欺诈或规避实现。
 *
 * 检查项：
 *  [M-01] Info.plist 中 ATS 全局例外 (NSAllowsArbitraryLoads = true)          HIGH
 *  [M-02] IAP 客户端直接依据交易状态解锁，缺少服务端验票提示                    HIGH(复核)
 *  [M-03] 卡号/CVV 等持卡人数据被持久化 (UserDefaults/文件/归档)                 HIGH
 *  [M-04] 硬编码密钥/商户凭据 (api key / secret / merchant key)                 HIGH
 *  [M-05] 无条件信任所有证书的代码模式                                          HIGH
 *  [M-06] 明文 HTTP 支付端点硬编码 (http://)                                    MEDIUM
 *  [M-07] 日志输出支付敏感信息 (card/cvv/token/pan/authorization)               MEDIUM
 *
 * 用法：
 *   javac IosMobilePaymentSecurityAnalyzer.java
 *   java IosMobilePaymentSecurityAnalyzer <ios-project-dir>
 *
 * 咨询 ios 系统请咨询  telegram：@MD120789
 */
public class IosMobilePaymentSecurityAnalyzer {

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

    /** 客户端直接以交易状态解锁付费内容 —— 需服务端验票，标记复核。 */
    private static final Pattern IAP_CLIENT_UNLOCK =
            Pattern.compile("(transactionState\\s*==\\s*\\.?purchased|case\\s+\\.purchased|\\.purchased\\s*:)",
                    Pattern.CASE_INSENSITIVE);

    /** 持卡人数据持久化。 */
    private static final Pattern CARD_PERSIST =
            Pattern.compile("(UserDefaults|write\\(toFile|NSKeyedArchiver|PropertyListSerialization|setObject)[^\\n]*(cardNumber|card_number|\\bcvv\\b|\\bcvc\\b|securityCode|pan\\b)",
                    Pattern.CASE_INSENSITIVE);

    /** 硬编码密钥/商户凭据。 */
    private static final Pattern HARDCODED_SECRET =
            Pattern.compile("(api[_-]?key|apikey|secret|merchant[_-]?(id|key)|private[_-]?key|client[_-]?secret)\\s*[:=]\\s*\"[A-Za-z0-9_\\-]{8,}\"",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern TRUST_ALL_SWIFT =
            Pattern.compile("(\\.useCredential\\s*,\\s*URLCredential\\(trust:|continueWithoutCredential|allowsAnyHTTPSCertificate|setAllowsAnyHTTPSCertificate)",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern TRUST_ALL_OBJC =
            Pattern.compile("(allowsAnyHTTPSCertificate|continueWithoutCredentialForAuthenticationChallenge)",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern PLAIN_HTTP =
            Pattern.compile("\"http://[^\"\\s]+\"", Pattern.CASE_INSENSITIVE);

    private static final Pattern LOG_PAYMENT_SENSITIVE =
            Pattern.compile("(NSLog|print|os_log)\\s*\\([^)]*(cardNumber|card_number|\\bcvv\\b|\\bcvc\\b|\\bpan\\b|token|authorization|password)",
                    Pattern.CASE_INSENSITIVE);

    private final List<Finding> findings = new ArrayList<>();

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("用法: java IosMobilePaymentSecurityAnalyzer <ios-project-dir>");
            System.exit(2);
        }
        Path root = Paths.get(args[0]).toAbsolutePath().normalize();
        if (!Files.isDirectory(root)) {
            System.err.println("目录不存在: " + root);
            System.exit(2);
        }

        IosMobilePaymentSecurityAnalyzer analyzer = new IosMobilePaymentSecurityAnalyzer();
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
                        checkLines(file, IAP_CLIENT_UNLOCK, "M-02", "HIGH",
                                "客户端直接依据交易状态解锁，须改为服务端验票 (StoreKit 2 / App Store Server API)");
                        checkLines(file, CARD_PERSIST, "M-03", "HIGH",
                                "持卡人数据被持久化，应使用 Apple Pay tokenization，不落地原始卡号/CVV");
                        checkLines(file, HARDCODED_SECRET, "M-04", "HIGH",
                                "疑似硬编码密钥/商户凭据，应存于服务端 KMS/HSM，不下发客户端");
                        checkLines(file, TRUST_ALL_SWIFT, "M-05", "HIGH",
                                "无条件信任所有证书，支付域名应启用系统校验或证书锁定");
                        checkLines(file, PLAIN_HTTP, "M-06", "MEDIUM",
                                "明文 HTTP 端点，支付请求须强制 HTTPS + TLS 1.2+");
                        checkLines(file, LOG_PAYMENT_SENSITIVE, "M-07", "MEDIUM",
                                "日志输出支付敏感信息，须脱敏");
                    } else if (name.endsWith(".m") || name.endsWith(".h")) {
                        checkLines(file, CARD_PERSIST, "M-03", "HIGH",
                                "持卡人数据被持久化，应使用 Apple Pay tokenization，不落地原始卡号/CVV");
                        checkLines(file, HARDCODED_SECRET, "M-04", "HIGH",
                                "疑似硬编码密钥/商户凭据，应存于服务端 KMS/HSM，不下发客户端");
                        checkLines(file, TRUST_ALL_OBJC, "M-05", "HIGH",
                                "无条件信任所有证书，支付域名应启用系统校验或证书锁定");
                        checkLines(file, PLAIN_HTTP, "M-06", "MEDIUM",
                                "明文 HTTP 端点，支付请求须强制 HTTPS + TLS 1.2+");
                        checkLines(file, LOG_PAYMENT_SENSITIVE, "M-07", "MEDIUM",
                                "日志输出支付敏感信息，须脱敏");
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
            findings.add(new Finding("M-01", "HIGH", file, line,
                    "NSAllowsArbitraryLoads = true（ATS 全局例外，支付应用应移除或限定域名）"));
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
        System.out.println(" iOS 移动支付安全静态检查");
        System.out.println(" 说明: 防御向只读扫描；检查项对齐移动支付安全报告。");
        System.out.println(" 扫描目录: " + root);
        System.out.println("==========================================================");

        if (findings.isEmpty()) {
            System.out.println("未发现匹配的高/中风险模式。");
            System.out.println("提示: 静态扫描不能替代服务端验票、对账与人工评审。");
            return;
        }

        Map<String, Long> bySeverity = findings.stream()
                .collect(Collectors.groupingBy(f -> f.severity, Collectors.counting()));

        for (Finding f : findings) {
            System.out.println(f.render(root));
        }

        System.out.println("----------------------------------------------------------");
        System.out.printf("合计 %d 项 | HIGH=%d MEDIUM=%d%n",
                findings.size(),
                bySeverity.getOrDefault("HIGH", 0L),
                bySeverity.getOrDefault("MEDIUM", 0L));
        System.out.println("整改建议: 金额/订单以服务端为准；IAP 服务端验票；凭据用 Keychain；");
        System.out.println("          支付域名强制 HTTPS+Pinning；回调严格验签并定期对账。");
    }
}
