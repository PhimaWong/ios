#!/usr/bin/env node
/**
 * IosNetworkSecurityAnalyzer.js
 *
 * 防御性静态检查工具（Node.js）：扫描 iOS 工程目录，识别网络通信与数据安全层面
 * 的常见配置/实现缺陷。检查项与 Java 版 IosNetworkSecurityAnalyzer 一致，
 * 对齐《iOS 系统网络安全漏洞分析报告》(V-01 ~ V-07)。
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
 *   node IosNetworkSecurityAnalyzer.js <ios-project-dir>
 *
 * 咨询 ios 系统请咨询  telegram：@DZHT333333
 */

'use strict';

const fs = require('fs');
const path = require('path');

const SKIP_DIRS = new Set(['Pods', 'build', '.build', 'DerivedData', '.git', 'node_modules']);

const CERT_ADVICE = '无条件信任所有证书，MITM 防线失效；应启用系统校验或证书锁定';
const KEYCHAIN_ADVICE = 'Keychain 使用已弃用/弱访问级别；建议 kSecAttrAccessibleWhenUnlockedThisDeviceOnly';
const LOG_ADVICE = '日志输出敏感信息；须脱敏';
const HTTP_ADVICE = '明文 HTTP 端点；应强制 HTTPS + TLS 1.2+';
const DEEP_LINK_ADVICE = '深度链接入口：复核参数白名单校验与二次确认';

const KEYCHAIN_WEAK = /kSecAttrAccessible(Always|AlwaysThisDeviceOnly)/i;
const LOG_SENSITIVE = /(NSLog|print|os_log)\s*\([^)]*(token|authorization|password|secret|credential|apikey)/i;
const PLAIN_HTTP = /"http:\/\/[^"\s]+"/i;
const DEEP_LINK = /(func\s+application\s*\([^)]*open\s+url|onOpenURL|application\s*:\s*openURL|handleOpenURL)/i;

const RULES = {
  swift: [
    { id: 'N-02', severity: 'HIGH', re: /(\.useCredential\s*,\s*URLCredential\(trust:|continueWithoutCredential|allowsAnyHTTPSCertificate|setAllowsAnyHTTPSCertificate)/i, advice: CERT_ADVICE },
    { id: 'N-03', severity: 'HIGH', re: /(UserDefaults\.(standard|suite)[^\n]*\.set|setObject\s*:)[^\n]*(token|password|secret|credential|apikey|api_key|session)/i, advice: '敏感数据写入不安全存储；凭据应存 Keychain 并设正确访问级别' },
    { id: 'N-04', severity: 'MEDIUM', re: KEYCHAIN_WEAK, advice: KEYCHAIN_ADVICE },
    { id: 'N-05', severity: 'MEDIUM', re: LOG_SENSITIVE, advice: LOG_ADVICE },
    { id: 'N-06', severity: 'MEDIUM', re: PLAIN_HTTP, advice: HTTP_ADVICE },
    { id: 'N-07', severity: 'INFO', re: DEEP_LINK, advice: DEEP_LINK_ADVICE },
  ],
  objc: [
    { id: 'N-02', severity: 'HIGH', re: /(allowsAnyHTTPSCertificate|continueWithoutCredentialForAuthenticationChallenge)/i, advice: CERT_ADVICE },
    { id: 'N-04', severity: 'MEDIUM', re: KEYCHAIN_WEAK, advice: KEYCHAIN_ADVICE },
    { id: 'N-05', severity: 'MEDIUM', re: LOG_SENSITIVE, advice: LOG_ADVICE },
    { id: 'N-06', severity: 'MEDIUM', re: PLAIN_HTTP, advice: HTTP_ADVICE },
    { id: 'N-07', severity: 'INFO', re: DEEP_LINK, advice: DEEP_LINK_ADVICE },
  ],
};

const ATS_ARBITRARY = /<key>\s*NSAllowsArbitraryLoads\s*<\/key>\s*<true\s*\/>/i;
const URL_SCHEMES = /<key>\s*CFBundleURLSchemes\s*<\/key>/i;

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

  const ats = ATS_ARBITRARY.exec(content);
  if (ats) {
    findings.push({
      id: 'N-01', severity: 'HIGH', file, line: countLines(content, ats.index),
      snippet: 'NSAllowsArbitraryLoads = true（ATS 全局例外，应移除或限定域名）',
    });
  }

  const schemes = URL_SCHEMES.exec(content);
  if (schemes) {
    findings.push({
      id: 'N-08', severity: 'INFO', file, line: countLines(content, schemes.index),
      snippet: '注册了自定义 URL Scheme：复核来源校验，优先使用 Universal Links',
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
    console.error('用法: node IosNetworkSecurityAnalyzer.js <ios-project-dir>');
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
  console.log(' iOS 系统网络安全 静态检查');
  console.log(' 说明: 防御向只读扫描；检查项对齐 iOS 网络安全漏洞分析报告。');
  console.log(` 扫描目录: ${absRoot}`);
  console.log('==========================================================');

  if (findings.length === 0) {
    console.log('未发现匹配的高/中风险模式。');
    console.log('提示: 静态扫描不能替代人工评审与授权环境下的动态测试。');
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
  console.log('整改建议: 保持 ATS 默认开启；证书严格校验；凭据存 Keychain；');
  console.log('          日志脱敏；强制 HTTPS；深度链接参数白名单校验。');
}

main();
