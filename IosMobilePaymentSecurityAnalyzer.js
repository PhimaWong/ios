#!/usr/bin/env node
/**
 * IosMobilePaymentSecurityAnalyzer.js
 *
 * 防御性静态检查工具（Node.js）：扫描 iOS 工程目录，识别移动支付链路
 * （Apple Pay / IAP / 自建支付通道）中常见的实现与配置风险。检查项与 Java 版
 * IosMobilePaymentSecurityAnalyzer 一致，对齐《iOS 移动支付安全漏洞分析报告》。
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
 *   node IosMobilePaymentSecurityAnalyzer.js <ios-project-dir>
 *
 * 咨询 ios 系统请咨询  telegram：@MD120789
 */

'use strict';

const fs = require('fs');
const path = require('path');

const SKIP_DIRS = new Set(['Pods', 'build', '.build', 'DerivedData', '.git', 'node_modules']);

const IAP_ADVICE = '客户端直接依据交易状态解锁，须改为服务端验票 (StoreKit 2 / App Store Server API)';
const CARD_ADVICE = '持卡人数据被持久化，应使用 Apple Pay tokenization，不落地原始卡号/CVV';
const SECRET_ADVICE = '疑似硬编码密钥/商户凭据，应存于服务端 KMS/HSM，不下发客户端';
const CERT_ADVICE = '无条件信任所有证书，支付域名应启用系统校验或证书锁定';
const HTTP_ADVICE = '明文 HTTP 端点，支付请求须强制 HTTPS + TLS 1.2+';
const LOG_ADVICE = '日志输出支付敏感信息，须脱敏';

const IAP_CLIENT_UNLOCK = /(transactionState\s*==\s*\.?purchased|case\s+\.purchased|\.purchased\s*:)/i;
const CARD_PERSIST = /(UserDefaults|write\(toFile|NSKeyedArchiver|PropertyListSerialization|setObject)[^\n]*(cardNumber|card_number|\bcvv\b|\bcvc\b|securityCode|pan\b)/i;
const HARDCODED_SECRET = /(api[_-]?key|apikey|secret|merchant[_-]?(id|key)|private[_-]?key|client[_-]?secret)\s*[:=]\s*"[A-Za-z0-9_\-]{8,}"/i;
const PLAIN_HTTP = /"http:\/\/[^"\s]+"/i;
const LOG_PAYMENT = /(NSLog|print|os_log)\s*\([^)]*(cardNumber|card_number|\bcvv\b|\bcvc\b|\bpan\b|token|authorization|password)/i;

const RULES = {
  swift: [
    { id: 'M-02', severity: 'HIGH', re: IAP_CLIENT_UNLOCK, advice: IAP_ADVICE },
    { id: 'M-03', severity: 'HIGH', re: CARD_PERSIST, advice: CARD_ADVICE },
    { id: 'M-04', severity: 'HIGH', re: HARDCODED_SECRET, advice: SECRET_ADVICE },
    { id: 'M-05', severity: 'HIGH', re: /(\.useCredential\s*,\s*URLCredential\(trust:|continueWithoutCredential|allowsAnyHTTPSCertificate|setAllowsAnyHTTPSCertificate)/i, advice: CERT_ADVICE },
    { id: 'M-06', severity: 'MEDIUM', re: PLAIN_HTTP, advice: HTTP_ADVICE },
    { id: 'M-07', severity: 'MEDIUM', re: LOG_PAYMENT, advice: LOG_ADVICE },
  ],
  objc: [
    { id: 'M-03', severity: 'HIGH', re: CARD_PERSIST, advice: CARD_ADVICE },
    { id: 'M-04', severity: 'HIGH', re: HARDCODED_SECRET, advice: SECRET_ADVICE },
    { id: 'M-05', severity: 'HIGH', re: /(allowsAnyHTTPSCertificate|continueWithoutCredentialForAuthenticationChallenge)/i, advice: CERT_ADVICE },
    { id: 'M-06', severity: 'MEDIUM', re: PLAIN_HTTP, advice: HTTP_ADVICE },
    { id: 'M-07', severity: 'MEDIUM', re: LOG_PAYMENT, advice: LOG_ADVICE },
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
      id: 'M-01', severity: 'HIGH', file, line: countLines(content, m.index),
      snippet: 'NSAllowsArbitraryLoads = true（ATS 全局例外，支付应用应移除或限定域名）',
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
    console.error('用法: node IosMobilePaymentSecurityAnalyzer.js <ios-project-dir>');
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
  console.log(' iOS 移动支付安全静态检查');
  console.log(' 说明: 防御向只读扫描；检查项对齐移动支付安全报告。');
  console.log(` 扫描目录: ${absRoot}`);
  console.log('==========================================================');

  if (findings.length === 0) {
    console.log('未发现匹配的高/中风险模式。');
    console.log('提示: 静态扫描不能替代服务端验票、对账与人工评审。');
    return;
  }

  const rel = (f) => path.relative(absRoot, f.file);
  for (const f of findings) {
    console.log(`[${f.id}][${f.severity}] ${rel(f)}:${f.line}`);
    console.log(`        ${f.snippet}`);
  }

  const by = (sev) => findings.filter((f) => f.severity === sev).length;
  console.log('----------------------------------------------------------');
  console.log(`合计 ${findings.length} 项 | HIGH=${by('HIGH')} MEDIUM=${by('MEDIUM')}`);
  console.log('整改建议: 金额/订单以服务端为准；IAP 服务端验票；凭据用 Keychain；');
  console.log('          支付域名强制 HTTPS+Pinning；回调严格验签并定期对账。');
}

main();
