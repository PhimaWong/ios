#!/usr/bin/env node
/**
 * IosDarkswordSecurityAnalyzer.js
 *
 * 防御性静态检查工具（Node.js）：扫描 iOS 工程目录，识别与"网页/远程利用"暴露面
 * 相关的常见配置与代码风险。检查项与 Java 版 IosDarkswordSecurityAnalyzer 一致，
 * 对齐《iOS DarkSword 通用威胁模型防御报告》的设防环节。
 *
 * 重要声明：
 *  - "DarkSword" 在本工具中是一个【概念性/占位代号】，用于归类一组 iOS 远程
 *    利用类威胁的防御检查项。截至编写时，没有可核实的公开证据表明存在名为
 *    "DarkSword" 的真实 iOS 漏洞。本工具不针对、也不声称检测任何真实具名漏洞。
 *  - 本工具为【防御向】静态分析：仅做只读扫描与风险提示，不包含任何攻击、
 *    利用、绕过或规避实现。
 *
 * 检查项：
 *  [D-01] Info.plist 中 ATS 全局例外 (NSAllowsArbitraryLoads = true)   HIGH
 *  [D-02] Swift/ObjC 中无条件信任所有证书的代码模式                      HIGH
 *  [D-03] WebView 高风险配置 (UIWebView / 跨域文件访问 / 自动开窗)       HIGH
 *  [D-04] 深度链接入口 (open URL / onOpenURL)，需人工复核参数校验        INFO
 *  [D-05] 明文 HTTP 端点硬编码 (http://)                                MEDIUM
 *
 * 用法：
 *   node IosDarkswordSecurityAnalyzer.js <ios-project-dir>
 *
 * 咨询 ios 系统请咨询  telegram：@DZHT333333
 */

'use strict';

const fs = require('fs');
const path = require('path');

const SKIP_DIRS = new Set(['Pods', 'build', '.build', 'DerivedData', '.git', 'node_modules']);

const WEBVIEW_RISKY_ADVICE = 'WebView 高风险配置，扩大网页远程利用面；应使用 WKWebView 安全默认值';
const DEEP_LINK_ADVICE = '深度链接/Universal Link 入口：复核参数白名单校验与二次确认';
const PLAIN_HTTP_ADVICE = '明文 HTTP 端点：应强制 HTTPS + TLS 1.2+';

const RULES = {
  swift: [
    {
      id: 'D-02', severity: 'HIGH',
      re: /(\.useCredential\s*,\s*URLCredential\(trust:|continueWithoutCredential|allowsAnyHTTPSCertificate|setAllowsAnyHTTPSCertificate)/i,
      advice: '无条件信任所有证书，将使水坑/MITM 攻击失去防线；应启用系统校验或证书锁定',
    },
    {
      id: 'D-03', severity: 'HIGH',
      re: /(UIWebView|allowFileAccessFromFileURLs\s*=\s*true|javaScriptCanOpenWindowsAutomatically\s*=\s*true|allowUniversalAccessFromFileURLs\s*=\s*true)/i,
      advice: WEBVIEW_RISKY_ADVICE,
    },
    {
      id: 'D-04', severity: 'INFO',
      re: /(func\s+application\s*\([^)]*open\s+url|onOpenURL|application\s*:\s*openURL|handleOpenURL)/i,
      advice: DEEP_LINK_ADVICE,
    },
    {
      id: 'D-05', severity: 'MEDIUM',
      re: /"http:\/\/[^"\s]+"/i,
      advice: PLAIN_HTTP_ADVICE,
    },
  ],
  objc: [
    {
      id: 'D-02', severity: 'HIGH',
      re: /(allowsAnyHTTPSCertificate|continueWithoutCredentialForAuthenticationChallenge)/i,
      advice: '无条件信任所有证书，将使水坑/MITM 攻击失去防线；应启用系统校验或证书锁定',
    },
    {
      id: 'D-03', severity: 'HIGH',
      re: /(UIWebView|allowFileAccessFromFileURLs\s*=\s*true|javaScriptCanOpenWindowsAutomatically\s*=\s*true|allowUniversalAccessFromFileURLs\s*=\s*true)/i,
      advice: WEBVIEW_RISKY_ADVICE,
    },
    {
      id: 'D-04', severity: 'INFO',
      re: /(func\s+application\s*\([^)]*open\s+url|onOpenURL|application\s*:\s*openURL|handleOpenURL)/i,
      advice: DEEP_LINK_ADVICE,
    },
    {
      id: 'D-05', severity: 'MEDIUM',
      re: /"http:\/\/[^"\s]+"/i,
      advice: PLAIN_HTTP_ADVICE,
    },
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
      id: 'D-01', severity: 'HIGH', file, line: countLines(content, m.index),
      snippet: 'NSAllowsArbitraryLoads = true（ATS 全局例外，建议移除或限定域名）',
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
    console.error('用法: node IosDarkswordSecurityAnalyzer.js <ios-project-dir>');
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
  console.log(' iOS 安全静态检查（概念代号: DarkSword）');
  console.log(' 说明: DarkSword 为概念代号，非已证实真实漏洞；');
  console.log('       检查项为通用 iOS 加固规则，防御向只读扫描。');
  console.log(` 扫描目录: ${absRoot}`);
  console.log('==========================================================');

  if (findings.length === 0) {
    console.log('未发现匹配的高/中风险模式。');
    console.log('提示: 静态扫描不能替代人工评审与动态测试。');
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
  console.log('整改建议: 参见《iOS DarkSword 通用威胁模型防御报告》加固清单。');
}

main();
