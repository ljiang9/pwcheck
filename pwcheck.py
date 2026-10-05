#!/usr/bin/env python3
"""pwcheck — 查密码是否出现在公开泄露库里，但密码本身从不出本机。

原理（k-anonymity）：只把 SHA-1 的前 5 个十六进制字符发给
HaveIBeenPwned 的 range API，返回所有同前缀的哈希后缀，
在本地比对计数。完整哈希永远不会离开本机。
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

API_URL = "https://api.pwnedpasswords.com/range/{}"
VERSION = "0.1.0"


def sha1_upper(password: str) -> str:
    """SHA-1 摘要，大写十六进制（与 HIBP API 约定一致）。"""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def split_hash(full: str) -> tuple[str, str]:
    """拆成 (前 5 字符前缀, 剩余 35 字符后缀)。"""
    return full[:5], full[5:]


def fetch_range(prefix: str, timeout: float = 15.0) -> str:
    """取同前缀的哈希后缀列表。只发 5 个字符，绝不多发。"""
    url = API_URL.format(prefix)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"pwcheck/{VERSION}"},
        method="GET",
    )
    # 走系统代理环境变量（沙箱/公司网常见）；urllib 默认就读 *_proxy
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"API 返回 HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"无法连接 API：{e.reason}") from e
    except TimeoutError as e:
        raise RuntimeError("连接 API 超时") from e


def count_leaks(body: str, suffix: str) -> int:
    """在返回体里找后缀命中，返回泄露次数。返回体格式：`SUFFIX:count` 每行一个。"""
    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        hash_suffix, count = line.split(":", 1)
        if hash_suffix.strip().upper() == suffix:
            return int(count.strip())
    return 0


def read_password() -> str:
    """交互式读密码：不回显、不进 argv、不写历史。非交互式（管道）仅用于测试。"""
    if not sys.stdin.isatty():
        # 测试模式：允许管道喂入（README 说明仅限测试用）
        data = sys.stdin.read()
        return data.splitlines()[0] if data else ""
    return getpass.getpass("请输入要检查的密码（不会显示）：")


def check(password: str, timeout: float = 15.0) -> tuple[int, str]:
    """返回 (泄露次数, 实际请求的 URL)。"""
    full = sha1_upper(password)
    prefix, suffix = split_hash(full)
    url = API_URL.format(prefix)
    body = fetch_range(prefix, timeout=timeout)
    return count_leaks(body, suffix), url


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pwcheck",
        description="检查密码是否出现在公开泄露库中（k-anonymity：完整哈希不出本机）。",
    )
    parser.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    parser.add_argument("--timeout", type=float, default=15.0, help="API 超时秒数（默认 15）")
    parser.add_argument("--version", action="version", version=f"pwcheck {VERSION}")
    args = parser.parse_args(argv)

    password = read_password()
    if not password:
        print("error: 没有输入密码", file=sys.stderr)
        return 2

    try:
        count, _url = check(password, timeout=args.timeout)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    finally:
        # 内存里尽量早清掉明文
        password = ""  # noqa: F841

    if args.json:
        print(json.dumps({"leaked": count > 0, "count": count}, ensure_ascii=False))
    elif count > 0:
        print(f"⚠️  该密码在已知泄露中出现 {count} 次，请立即更换。")
        print("   （这只说明它进过公开泄露库；未出现也不等于密码够强。）")
    else:
        print("✅ 未在已知泄露库中出现。")
        print("   （只查了公开泄露语料；密码强度请用 pwcheck 的兄弟项目 passgen 生成高熵密码。）")
    return 1 if count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
