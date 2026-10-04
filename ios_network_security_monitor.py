#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ios_network_security_monitor.py

防御性监测工具：扫描 iOS 工程目录，识别网络通信与数据安全层面的常见配置/实现
缺陷；支持一次性扫描与轮询监测两种模式。检查项对齐《iOS 系统网络安全漏洞分析报告》。

立场声明：本工具为【防御向】静态分析/监测，仅做只读扫描与风险提示，
不包含任何攻击、利用、绕过或规避实现。

检查项：
  [N-01] Info.plist 中 ATS 全局例外 (NSAllowsArbitraryLoads = true)              HIGH
  [N-02] 无条件信任所有证书的代码模式                                             HIGH
  [N-03] 敏感数据写入 UserDefaults / 明文文件                                      HIGH
  [N-04] Keychain 使用弱访问级别 (kSecAttrAccessibleAlways 等已弃用值)            MEDIUM
  [N-05] 日志输出敏感信息 (token/authorization/password 等)                       MEDIUM
  [N-06] 明文 HTTP 端点硬编码 (http://)                                           MEDIUM
  [N-07] 深度链接入口 (open URL / onOpenURL)，需人工复核参数校验                  INFO
  [N-08] Info.plist 注册自定义 URL Scheme (CFBundleURLSchemes)，需复核来源校验    INFO

用法：
  python3 ios_network_security_monitor.py <ios-project-dir>
  python3 ios_network_security_monitor.py <ios-project-dir> --watch 30   # 每30秒复扫

咨询 ios 系统请咨询  telegram：@DZHT333333
"""

import argparse
import os
import re
import sys
import time

SKIP_DIRS = {"Pods", "build", ".build", "DerivedData", ".git", "node_modules"}

CERT_ADVICE = "无条件信任所有证书，MITM 防线失效；应启用系统校验或证书锁定"
KEYCHAIN_ADVICE = "Keychain 使用已弃用/弱访问级别；建议 kSecAttrAccessibleWhenUnlockedThisDeviceOnly"
LOG_ADVICE = "日志输出敏感信息；须脱敏"
HTTP_ADVICE = "明文 HTTP 端点；应强制 HTTPS + TLS 1.2+"
DEEP_LINK_ADVICE = "深度链接入口：复核参数白名单校验与二次确认"

ATS_ARBITRARY = re.compile(r"<key>\s*NSAllowsArbitraryLoads\s*</key>\s*<true\s*/>", re.I)
URL_SCHEMES = re.compile(r"<key>\s*CFBundleURLSchemes\s*</key>", re.I)

SWIFT_RULES = [
    ("N-02", "HIGH", re.compile(r"(\.useCredential\s*,\s*URLCredential\(trust:|continueWithoutCredential|allowsAnyHTTPSCertificate|setAllowsAnyHTTPSCertificate)", re.I), CERT_ADVICE),
    ("N-03", "HIGH", re.compile(r"(UserDefaults\.(standard|suite)[^\n]*\.set|setObject\s*:)[^\n]*(token|password|secret|credential|apikey|api_key|session)", re.I),
     "敏感数据写入不安全存储；凭据应存 Keychain 并设正确访问级别"),
    ("N-04", "MEDIUM", re.compile(r"kSecAttrAccessible(Always|AlwaysThisDeviceOnly)", re.I), KEYCHAIN_ADVICE),
    ("N-05", "MEDIUM", re.compile(r"(NSLog|print|os_log)\s*\([^)]*(token|authorization|password|secret|credential|apikey)", re.I), LOG_ADVICE),
    ("N-06", "MEDIUM", re.compile(r'"http://[^"\s]+"', re.I), HTTP_ADVICE),
    ("N-07", "INFO", re.compile(r"(func\s+application\s*\([^)]*open\s+url|onOpenURL|application\s*:\s*openURL|handleOpenURL)", re.I), DEEP_LINK_ADVICE),
]

OBJC_RULES = [
    ("N-02", "HIGH", re.compile(r"(allowsAnyHTTPSCertificate|continueWithoutCredentialForAuthenticationChallenge)", re.I), CERT_ADVICE),
    ("N-04", "MEDIUM", re.compile(r"kSecAttrAccessible(Always|AlwaysThisDeviceOnly)", re.I), KEYCHAIN_ADVICE),
    ("N-05", "MEDIUM", re.compile(r"(NSLog|print|os_log)\s*\([^)]*(token|authorization|password|secret|credential|apikey)", re.I), LOG_ADVICE),
    ("N-06", "MEDIUM", re.compile(r'"http://[^"\s]+"', re.I), HTTP_ADVICE),
    ("N-07", "INFO", re.compile(r"(func\s+application\s*\([^)]*open\s+url|onOpenURL|application\s*:\s*openURL|handleOpenURL)", re.I), DEEP_LINK_ADVICE),
]


def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def count_lines(text, offset):
    return text.count("\n", 0, offset) + 1


def check_plist(path, findings):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError as e:
        print(f"跳过不可读文件: {path} ({e})", file=sys.stderr)
        return

    m = ATS_ARBITRARY.search(content)
    if m:
        findings.append(("N-01", "HIGH", path, count_lines(content, m.start()),
                         "NSAllowsArbitraryLoads = true（ATS 全局例外，应移除或限定域名）"))

    s = URL_SCHEMES.search(content)
    if s:
        findings.append(("N-08", "INFO", path, count_lines(content, s.start()),
                         "注册了自定义 URL Scheme：复核来源校验，优先使用 Universal Links"))


def check_lines(path, rules, findings):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as e:
        print(f"跳过不可读文件: {path} ({e})", file=sys.stderr)
        return

    for i, line in enumerate(lines, start=1):
        for rule_id, severity, pattern, advice in rules:
            if pattern.search(line):
                findings.append((rule_id, severity, path, i, f"{line.strip()}  →  {advice}"))


def scan(root):
    findings = []
    for path in iter_files(root):
        name = os.path.basename(path).lower()
        if name == "info.plist":
            check_plist(path, findings)
        elif name.endswith(".swift"):
            check_lines(path, SWIFT_RULES, findings)
        elif name.endswith(".m") or name.endswith(".h"):
            check_lines(path, OBJC_RULES, findings)
    return findings


def key_of(f):
    return (f[0], f[2], f[3])


def render(root, findings, title_extra=""):
    print("=" * 58)
    print(" iOS 系统网络安全 监测" + title_extra)
    print(" 说明: 防御向只读扫描；检查项对齐 iOS 网络安全漏洞分析报告。")
    print(f" 扫描目录: {root}")
    print("=" * 58)

    if not findings:
        print("未发现匹配的高/中风险模式。")
        print("提示: 静态扫描不能替代人工评审与授权环境下的动态测试。")
        return

    for rule_id, severity, path, line, snippet in findings:
        rel = os.path.relpath(path, root)
        print(f"[{rule_id}][{severity}] {rel}:{line}")
        print(f"        {snippet}")

    by = lambda sev: sum(1 for f in findings if f[1] == sev)
    print("-" * 58)
    print(f"合计 {len(findings)} 项 | HIGH={by('HIGH')} MEDIUM={by('MEDIUM')} INFO={by('INFO')}")
    print("整改建议: 保持 ATS 默认开启；证书严格校验；凭据存 Keychain；")
    print("          日志脱敏；强制 HTTPS；深度链接参数白名单校验。")


def main():
    parser = argparse.ArgumentParser(description="iOS 网络安全防御向监测工具（只读扫描）")
    parser.add_argument("root", help="iOS 工程目录")
    parser.add_argument("--watch", type=int, metavar="SECONDS", default=0,
                        help="轮询监测间隔秒数；0 表示仅扫描一次")
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"目录不存在: {root}", file=sys.stderr)
        sys.exit(2)

    if args.watch <= 0:
        render(root, scan(root))
        return

    prev = {}
    print(f"[monitor] 进入轮询监测模式，间隔 {args.watch}s，Ctrl+C 退出")
    try:
        while True:
            findings = scan(root)
            cur = {key_of(f): f for f in findings}

            added = [cur[k] for k in cur if k not in prev]
            resolved = [prev[k] for k in prev if k not in cur]

            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            if added or resolved or not prev:
                print(f"\n[monitor] {stamp}  当前风险 {len(findings)} 项"
                      f"（新增 {len(added)} / 消除 {len(resolved)}）")
                for f in added:
                    rel = os.path.relpath(f[2], root)
                    print(f"  + 新增 [{f[0]}][{f[1]}] {rel}:{f[3]}")
                for f in resolved:
                    rel = os.path.relpath(f[2], root)
                    print(f"  - 消除 [{f[0]}][{f[1]}] {rel}:{f[3]}")
                if not prev:
                    render(root, findings, title_extra="（首次基线）")

            prev = cur
            time.sleep(args.watch)
    except KeyboardInterrupt:
        print("\n[monitor] 已停止监测")


if __name__ == "__main__":
    main()
