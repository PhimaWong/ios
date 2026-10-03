#!/usr/bin/env node
/**
 * IosWateringHoleWebDefenseAnalyzer.js
 *
 * 防御性静态检查工具（Node.js）：扫描 iOS 工程目录，识别与"水坑攻击 / 网页远程
 * 利用"暴露面相关的常见配置与代码风险。检查项与 Java 版
 * IosWateringHoleWebDefenseAnalyzer 一致，对齐《iOS 水坑攻击与网页远程利用防御分析报告》。
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
 *   node IosWateringHoleWebDefenseAnalyzer.js <ios-project-dir>
 *
 * 咨询 ios 系统请咨询  telegram：@DZHT333333
 */

'use strict';

const fs = require('fs');
const path = require('path');

const SKIP_DIRS = new Set(['Pods', 'build', '.build', 'DerivedData', '.git', 'node_modules']);

const CERT_ADVICE = '无条件信任所有证书，将使水坑/MITM 攻击失去防线；应启用系统校验或证书锁定';
const WEBVIEW_ADVICE = 'WebView 高风险配置，扩大网页远程利用面；应使用 WKWebView 安全默认值';
const WEBVIEW_LOAD_ADVICE = 'WebView 加载内容入口：复核是否限定可信源、校验来源、兼容锁定模式';
const DEEP_LINK_ADVICE = '深度链接/Universal Link 入口：复核参数白名单校验与二次确认';
const HTTP_ADVICE = '明文 HTTP 端点：水坑站点可被篡改/窃听，应强制 HTTPS';
const LOG_URL_ADVICE = '日志可能泄露带凭据的 URL：应脱敏 query 参数';

const WEBVIEW_RISKY = /(UIWebView|allowFileAccessFromFileURLs\s*=\s*true|allowUniversalAccessFromFileURLs\s*=\s*true|javaScriptCanOpenWindowsAutomatically\s*=\s*true)/i;
const DEEP_LINK = /(func\s+application\s*\([^)]*open\s+url|onOpenURL|application\s*:\s*openURL|handleOpenURL|continue\s+userActivity)/i;
const PLAIN_HTTP = /"http:\/\/[^"\s]+"/i;
const LOG_URL_WITH_CRED = /(NSLog|print|os_log)\s*\([^)]*(\?[^"\s)]*(token|key|secret|auth|session)=|absoluteString)/i;

const RULES = {
  swift: [
    { id: 'W-02', severity: 'HIGH', re: /(\.useCredential\s*,\s*URLCredential\(trust:|continueWithoutCredential|allowsAnyHTTPSCertificate|setAllowsAnyHTTPSCertificate)/i, advice: CERT_ADVICE },
    { id: 'W-03', severity: 'HIGH', re: WEBVIEW_RISKY, advice: WEBVIEW_ADVICE },
    { id: 'W-04', severity: 'INFO', re: /(\.load\s*\(\s*URLRequest|loadHTMLString|\.loadFileURL|WKWebView\s*\()/i, advice: WEBVIEW_LOAD_ADVICE },
    { id: 'W-05', severity: 'INFO', re: DEEP_LINK, advice: DEEP_LINK_ADVICE },
    { id: 'W-06', severity: 'MEDIUM', re: PLAIN_HTTP, advice: HTTP_ADVICE },
    { id: 'W-07', severity: 'MEDIUM', re: LOG_URL_WITH_CRED, advice: LOG_URL_ADVICE },
  ],
  objc: [
    { id: 'W-02', severity: 'HIGH', re: /(allowsAnyHTTPSCertificate|continueWithoutCredentialForAuthenticationChallenge)/i, advice: CERT_ADVICE },
    { id: 'W-03', severity: 'HIGH', re: WEBVIEW_RISKY, advice: WEBVIEW_ADVICE },
    { id: 'W-05', severity: 'INFO', re: DEEP_LINK, advice: DEEP_LINK_ADVICE },
    { id: 'W-06', severity: 'MEDIUM', re: PLAIN_HTTP, advice: HTTP_ADVICE },
    { id: 'W-07', severity: 'MEDIUM', re: LOG_URL_WITH_CRED, advice: LOG_URL_ADVICE },
  ],
};

const ATS_ARBITRARY = /<key>\s*NSAllowsArbitraryLoads\s*<\/key>\s*<true\s*\/>/i;

function countLines(text, offset) {
  let n = 1;
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text[i] === '\n') n++;
  }
  return n;
}

function walk(dir, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walk(full, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

function checkPlist(file, findings) {
  const content = fs.readFileSync(file, 'utf8');
  const m = ATS_ARBITRARY.exec(content);
  if (m) {
    findings.push({
      id: 'W-01', severity: 'HIGH', file, line: countLines(content, m.index),
      snippet: 'NSAllowsArbitraryLoads = true（ATS 全局例外，扩大水坑/明文传输风险，应移除或限定域名）',
    });
  }
}

function checkLines(file, rules, findings) {
  let lines;
  try {
    lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
  } catch (e) {
    console.error(`跳过不可读文件: ${file} (${e.message})`);
    return;
  }
  lines.forEach((line, i) => {
    for (const rule of rules) {
      if (rule.re.test(line)) {
        findings.push({
          id: rule.id, severity: rule.severity, file, line: i + 1,
          snippet: `${line.trim()}  →  ${rule.advice}`,
        });
      }
    }
  });
}

function main() {
  const root = process.argv[2];
  if (!root) {
    console.error('用法: node IosWateringHoleWebDefenseAnalyzer.js <ios-project-dir>');
    process.exit(2);
  }
  const absRoot = path.resolve(root);
  if (!fs.existsSync(absRoot) || !fs.statSync(absRoot).isDirectory()) {
    console.error(`目录不存在: ${absRoot}`);
    process.exit(2);
  }

  const findings = [];
  for (const file of walk(absRoot, [])) {
    const name = path.basename(file).toLowerCase();
    if (name === 'info.plist') {
      checkPlist(file, findings);
    } else if (name.endsWith('.swift')) {
      checkLines(file, RULES.swift, findings);
    } else if (name.endsWith('.m') || name.endsWith('.h')) {
      checkLines(file, RULES.objc, findings);
    }
  }

  console.log('==========================================================');
  console.log(' iOS 水坑攻击 / 网页远程利用 防御静态检查');
  console.log(' 说明: 防御向只读扫描；检查项对齐水坑攻击防御报告。');
  console.log(` 扫描目录: ${absRoot}`);
  console.log('==========================================================');

  if (findings.length === 0) {
    console.log('未发现匹配的高/中风险模式。');
    console.log('提示: 保持系统更新、高风险人群启用锁定模式是最有效的纵深防线。');
    return;
  }

  const rel = (f) => path.relative(absRoot, f.file);
  for (const f of findings) {
    console.log(`[${f.id}][${f.severity}] ${rel(f)}:${f.line}`);
    console.log(`        ${f.snippet}`);
  }

  const by = (sev) => findings.filter((f) => f.severity === sev).length;
  console.log('----------------------------------------------------------');
  console.log(`合计 ${findings.length} 项 | HIGH=${by('HIGH')} MEDIUM=${by('MEDIUM')} INFO=${by('INFO')}`);
  console.log('整改建议: 强制 HTTPS+证书校验；收窄 WebView 配置与加载源；');
  console.log('          深度链接参数白名单校验；URL 日志脱敏；保持系统更新。');
}

main();
