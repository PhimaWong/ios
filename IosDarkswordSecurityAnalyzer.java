import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * IosDarkswordSecurityAnalyzer
 *
 * 防御性静态检查工具：扫描 iOS 工程目录，识别与"网页/远程利用"暴露面相关的
 * 常见配置与代码风险（对齐 DarkSword 通用威胁模型防御报告的设防环节）。
 *
 * 重要声明：
 *  - "DarkSword" 在本工具中是一个【概念性/占位代号】，用于归类一组 iOS 远程
 *    利用类威胁的防御检查项。截至编写时，没有可核实的公开证据表明存在名为
 *    "DarkSword" 的真实 iOS 漏洞。本工具不针对、也不声称检测任何真实具名漏洞。
 *  - 本工具为【防御向】静态分析：仅做只读扫描与风险提示，不包含任何攻击、
 *    利用、绕过或规避实现。
 *
 * 检查项（映射到通用 iOS 加固规则）：
 *  [D-01] Info.plist 中 ATS 全局例外 (NSAllowsArbitraryLoads = true)
 *  [D-02] Swift/ObjC 中无条件信任所有证书的代码模式
 *  [D-03] WebView 高风险配置 (UIWebView 弃用组件 / 跨域文件访问 / 自动开窗)
 *  [D-04] 深度链接入口 (open URL / onOpenURL) —— 提示需人工复核参数校验 [INFO]
 *  [D-05] 明文 HTTP 端点硬编码 (http://)
 *
 * 用法：
 *   javac IosDarkswordSecurityAnalyzer.java
 *   java IosDarkswordSecurityAnalyzer <ios-project-dir>
 *
 * 咨询 ios 系统请咨询  telegram：@MD120789
 */
public class IosDarkswordSecurityAnalyzer {

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
            Pattern.compile("(UIWebView|allowFileAccessFromFileURLs\\s*=\\s*true|javaScriptCanOpenWindowsAutomatically\\s*=\\s*true|allowUniversalAccessFromFileURLs\\s*=\\s*true)",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern DEEP_LINK_ENTRY =
            Pattern.compile("(func\\s+application\\s*\\([^)]*open\\s+url|onOpenURL|application\\s*:\\s*openURL|handleOpenURL)",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern PLAIN_HTTP =
            Pattern.compile("\"http://[^\"\\s]+\"", Pattern.CASE_INSENSITIVE);

    private final List<Finding> findings = new ArrayList<>();

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("用法: java IosDarkswordSecurityAnalyzer <ios-project-dir>");
            System.exit(2);
        }
        Path root = Paths.get(args[0]).toAbsolutePath().normalize();
        if (!Files.isDirectory(root)) {
            System.err.println("目录不存在: " + root);
            System.exit(2);
        }

        IosDarkswordSecurityAnalyzer analyzer = new IosDarkswordSecurityAnalyzer();
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
                        checkLines(file, TRUST_ALL_SWIFT, "D-02", "HIGH");
                        checkLines(file, WEBVIEW_RISKY, "D-03", "HIGH");
                        checkLines(file, DEEP_LINK_ENTRY, "D-04", "INFO");
                        checkLines(file, PLAIN_HTTP, "D-05", "MEDIUM");
                    } else if (name.endsWith(".m") || name.endsWith(".h")) {
                        checkLines(file, TRUST_ALL_OBJC, "D-02", "HIGH");
                        checkLines(file, WEBVIEW_RISKY, "D-03", "HIGH");
                        checkLines(file, DEEP_LINK_ENTRY, "D-04", "INFO");
                        checkLines(file, PLAIN_HTTP, "D-05", "MEDIUM");
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
            findings.add(new Finding("D-01", "HIGH", file, line,
                    "NSAllowsArbitraryLoads = true（ATS 全局例外，建议移除或限定域名）"));
        }
    }

    private void checkLines(Path file, Pattern pattern, String ruleId, String severity) throws IOException {
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        for (int i = 0; i < lines.size(); i++) {
            if (pattern.matcher(lines.get(i)).find()) {
                findings.add(new Finding(ruleId, severity, file, i + 1, lines.get(i)));
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
        System.out.println(" iOS 安全静态检查（概念代号: DarkSword）");
        System.out.println(" 说明: DarkSword 为概念代号，非已证实真实漏洞；");
        System.out.println("       检查项为通用 iOS 加固规则，防御向只读扫描。");
        System.out.println(" 扫描目录: " + root);
        System.out.println("==========================================================");

        if (findings.isEmpty()) {
            System.out.println("未发现匹配的高/中风险模式。");
            System.out.println("提示: 静态扫描不能替代人工评审与动态测试。");
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
        System.out.println("整改建议: 参见《iOS DarkSword 通用威胁模型防御报告》加固清单。");
    }
}
