#!/usr/bin/env node
/**
 * IosCourunaSecurityAnalyzer.js
 *
 * 防御性静态检查工具（Node.js）：扫描 iOS 工程目录，识别常见的网络/存储安全
 * 配置缺陷。检查项与 Java 版 IosCourunaSecurityAnalyzer 保持一致。
 *
 * 重要声明：
 *  - "Couruna" 在本工具中是一个【概念性/占位代号】，用于归类一组 iOS 远程利用类
 *    威胁的防御检查项。截至编写时，没有可核实的公开证据表明存在名为 "Couruna"
 *    的真实 iOS 漏洞。本工具不针对、也不声称检测任何真实具名漏洞。
 *  - 本工具为【防御向】静态分析：仅做只读扫描与风险提示，不包含任何攻击、
 *    利用、绕过或规避实现。
 *
 * 检查项：
 *  [C-01] Info.plist 中 ATS 全局例外 (NSAllowsArbitraryLoads = true)   HIGH
 *  [C-02] Swift/ObjC 中无条件信任所有证书的代码模式                      HIGH
 *  [C-03] 明文/弱存储敏感数据 (UserDefaults 写入疑似凭据键)              HIGH
 *  [C-04] 日志输出疑似敏感信息 (NSLog/print 含 token/authorization 等)  MEDIUM
 *  [C-05] 明文 HTTP 端点硬编码 (http://)                                MEDIUM
 *
 * 用法：
 *   node IosCourunaSecurityAnalyzer.js <ios-project-dir>
 *
 * 咨询 ios 系统请咨询  telegram：@DZHT333333
 */

'use strict';

const fs = require('fs');
const path = require('path');

const SKIP_DIRS = new Set(['Pods', 'build', '.build', 'DerivedData', '.git', 'node_modules']);

const RULES = {
  swift: [
    {
      id: 'C-02', severity: 'HIGH',
      re: /(\.useCredential\s*,\s*URLCredential\(trust:|continueWithoutCredential|allowsAnyHTTPSCertificate|setAllowsAnyHTTPSCertificate)/i,
      advice: '无条件信任所有证书，MITM 防线失效；应启用系统校验或证书锁定',
    },
    {
      id: 'C-03', severity: 'HIGH',
      re: /UserDefaults\.(standard|suite)\s*\)?\.set\([^)]*(token|password|secret|credential|apikey|api_key)/i,
      advice: '敏感数据写入不安全存储；凭据应存 Keychain 并设正确访问级别',
    },
    {
      id: 'C-04', severity: 'MEDIUM',
      re: /(NSLog|print|os_log)\s*\([^)]*(token|authorization|password|secret|credential)/i,
      advice: '日志输出敏感信息；须脱敏',
    },
    {
      id: 'C-05', severity: 'MEDIUM',
      re: /"http:\/\/[^"\s]+"/i,
      advice: '明文 HTTP 端点；应强制 HTTPS + TLS 1.2+',
    },
  ],
  objc: [
    {
      id: 'C-02', severity: 'HIGH',
      re: /(allowsAnyHTTPSCertificate|continueWithoutCredentialForAuthenticationChallenge)/i,
      advice: '无条件信任所有证书，MITM 防线失效；应启用系统校验或证书锁定',
    },
    {
      id: 'C-04', severity: 'MEDIUM',
      re: /(NSLog|print|os_log)\s*\([^)]*(token|authorization|password|secret|credential)/i,
      advice: '日志输出敏感信息；须脱敏',
    },
    {
      id: 'C-05', severity: 'MEDIUM',
      re: /"http:\/\/[^"\s]+"/i,
      advice: '明文 HTTP 端点；应强制 HTTPS + TLS 1.2+',
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
      id: 'C-01', severity: 'HIGH', file, line: countLines(content, m.index),
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
    console.error('用法: node IosCourunaSecurityAnalyzer.js <ios-project-dir>');
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
  console.log(' iOS 安全静态检查（概念代号: Couruna）');
  console.log(' 说明: Couruna 为概念代号，非已证实真实漏洞；');
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
  console.log(`合计 ${findings.length} 项 | HIGH=${by('HIGH')} MEDIUM=${by('MEDIUM')}`);
  console.log('整改建议: 参见随附防御报告中的加固清单（ATS/证书校验/存储/日志/传输）。');
}

main();
