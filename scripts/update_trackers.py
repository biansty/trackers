#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import hashlib
import urllib.request
import ssl
from datetime import datetime

# === 你可修改的常量（见下方“你需要修改的部分”） ===
SOURCES = [
    "https://ngosang.github.io/trackerslist/trackers_best.txt",
    "http://github.itzmx.com/1265578519/OpenTracker/master/tracker.txt",
    "https://raw.githubusercontent.com/adysec/tracker/refs/heads/main/trackers_all.txt",
    "https://cf.trackerslist.com/all.txt",
    "https://cf.trackerslist.com/http.txt",
]
OUTPUT_PATH = "trackers.txt"  # 输出文件路径（相对仓库根目录）
TIMEOUT_SECONDS = 25          # 请求超时时间
USER_AGENT = "Mozilla/5.0 (GitHubActions Bot)"

# 是否仅保留以某些协议开头的行；如需只保留 UDP/HTTP，可设置如下：
# ALLOWED_PREFIXES = ("udp://", "http://", "https://")
ALLOWED_PREFIXES = None  # None 表示不过滤协议前缀

def fetch_url(url: str) -> str:
    """
    下载 URL 文本，返回 str（失败时返回空字符串）
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        # 允许 https 的默认上下文
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS, context=ctx) as resp:
            # 尝试按原始字节推断编码
            content_bytes = resp.read()
            for enc in ("utf-8", "latin-1"):
                try:
                    return content_bytes.decode(enc)
                except UnicodeDecodeError:
                    continue
            # 最后兜底：忽略错误
            return content_bytes.decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[WARN] 下载失败: {url} | {e}", file=sys.stderr)
        return ""

def clean_lines(text: str):
    """
    清洗文本：按行分割，去除空白、过滤注释与空行、可选协议过滤
    """
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith(";"):
            continue
        if ALLOWED_PREFIXES is not None:
            if not any(line.lower().startswith(p) for p in ALLOWED_PREFIXES):
                continue
        lines.append(line)
    return lines

def dedup_and_sort(items):
    """
    去重并排序
    """
    return sorted(set(items), key=lambda s: s.lower())

def file_sha256(path: str) -> str:
    """
    计算文件 sha256（不存在返回空字符串）
    """
    if not os.path.isfile(path):
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    print("[INFO] 开始下载 trackers 列表...")
    all_lines = []
    for url in SOURCES:
        txt = fetch_url(url)
        if not txt:
            continue
        lines = clean_lines(txt)
        print(f"[INFO] 来源 {url} -> {len(lines)} 条")
        all_lines.extend(lines)

    merged = dedup_and_sort(all_lines)
    print(f"[INFO] 合并后共 {len(merged)} 条")

    # 准备文件内容，加上生成说明头
    header = [
        "# trackers.txt (auto-generated)",
        f"# sources: {len(SOURCES)}",
        f"# generated at: {datetime.utcnow().isoformat()}Z",
        "# -----------------------------------------------",
    ]
    final_text = "\n".join(header + merged) + "\n"

    old_hash = file_sha256(OUTPUT_PATH)
    new_hash = hashlib.sha256(final_text.encode("utf-8")).hexdigest()

    if old_hash == new_hash:
        print("[INFO] 内容未变化，跳过写入。")
        return

    # 写入文件
    with open(OUTPUT_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write(final_text)

    print(f"[INFO] 已写入 {OUTPUT_PATH}（内容有变化）。")

if __name__ == "__main__":
    main()
