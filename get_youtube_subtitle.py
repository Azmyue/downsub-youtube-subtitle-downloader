#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Download YouTube subtitles via DownSub's public endpoints (client-side flow replication).

Usage:
  python get_youtube_subtitle.py "<youtube_url>" [--lang zh-CN] [--out .\\dl] [--list]

If no URL is provided, it will prompt in the terminal.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import random
from urllib.parse import quote

import requests
from Crypto.Cipher import AES


DEFAULT_KEY = "zthxw34cdp6wfyxmpad38v52t3hsz6c5"

YOUTUBE_RE = re.compile(
    r"^(?:http(?:s)?:\/\/)?(?:www\.)?(?:m\.)?"
    r"(?:youtu\.be\/|youtube\.com\/(?:(?:watch|live)?\?(?:.*&)?v(?:i)?=|(?:embed|v|vi|user|shorts|live)\/))"
    r'([^\?&"\'>]+)'
    r"(?:(?:&|.+)?list=([a-zA-Z0-9_-]+))?"
)


def _evp_bytes_to_key_md5(password: bytes, salt8: bytes, key_len: int, iv_len: int) -> tuple[bytes, bytes]:
    """
    OpenSSL EVP_BytesToKey compatible with CryptoJS password-based AES (MD5, 1 iteration).
    """
    d = b""
    prev = b""
    while len(d) < (key_len + iv_len):
        prev = hashlib.md5(prev + password + salt8).digest()
        d += prev
    return d[:key_len], d[key_len : key_len + iv_len]


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _pt_base64_url_like(s: str) -> str:
    """
    Mimic DownSub bundle Pt():
      e=btoa(t); e=e.replace("+","-"); e=e.replace("/","_"); e=e.replace("=","")
    Important: single replacements only (not global) and only remove one '='.
    """
    b64 = base64.b64encode(s.encode("utf-8")).decode("ascii")
    b64 = b64.replace("+", "-", 1)
    b64 = b64.replace("/", "_", 1)
    b64 = b64.replace("=", "", 1)
    return b64.strip()


def encode_cryptojs_aes_json(data_obj, key: str = DEFAULT_KEY) -> str:
    """
    CryptoJS.AES.encrypt(JSON.stringify(data_obj), key, {format: Mt}).toString(), then Pt().

    Mt formatter outputs JSON:
      {"ct": base64(ciphertext), "iv": hex(iv), "s": hex(salt)}
    """
    if data_obj is None or data_obj == "":
        return ""

    plaintext = json.dumps(data_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    salt8 = os.urandom(8)
    key_bytes, iv = _evp_bytes_to_key_md5(key.encode("utf-8"), salt8, 32, 16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(_pkcs7_pad(plaintext, 16))

    mt = {
        "ct": base64.b64encode(ct).decode("ascii"),
        "iv": iv.hex(),
        "s": salt8.hex(),
    }
    mt_str = json.dumps(mt, ensure_ascii=False, separators=(",", ":"))
    return _pt_base64_url_like(mt_str)


def safe_filename(s: str) -> str:
    s = (s or "subtitle").strip()
    s = re.sub(r'[\\/:*?"<>|]+', "_", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:120] if len(s) > 120 else s


def guess_ext(content_type: str) -> str:
    ct = (content_type or "").lower()
    if "x-subrip" in ct:
        return ".srt"
    if "text/vtt" in ct:
        return ".vtt"
    if "text/plain" in ct:
        return ".txt"
    return ".srt"


def get_info_with_retry(enc_id: str, session: requests.Session, retries: int = 12) -> dict:
    url = f"https://get-info.downsub.com/{enc_id}"
    last = None
    for i in range(retries):
        r = session.get(url, timeout=30)
        last = r
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}

        if r.status_code == 200 and isinstance(data, dict) and "subtitles" in data:
            return data

        # Transient behaviors: 503 + {"error":"Video not found or unavailable"}.
        if r.status_code in (429, 503) or (500 <= r.status_code <= 599):
            # Exponential backoff with jitter, capped.
            delay = min(8.0, 0.7 * (2**i)) + random.random() * 0.3
            time.sleep(delay)
            continue

        raise RuntimeError(f"get-info failed: {r.status_code} {data}")

    raise RuntimeError(f"get-info failed after retries: {getattr(last, 'status_code', None)}")


def pick_subtitle(data: dict, lang: str | None) -> dict | None:
    subs = data.get("subtitles") or []
    trans = data.get("subtitlesAutoTrans") or []

    def find_in(pool):
        for x in pool:
            if not isinstance(x, dict):
                continue
            if lang and (x.get("code") == lang or x.get("name") == lang):
                return x
        return None

    if lang:
        hit = find_in(subs) or find_in(trans)
        if hit:
            return hit

    if subs:
        return subs[0]
    if trans:
        return trans[0]
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?", help="YouTube URL")
    ap.add_argument("--lang", default=None, help="Subtitle code/name, e.g. zh-CN / zh / English")
    ap.add_argument("--out", default="dl", help="Output directory (default: ./dl)")
    ap.add_argument("--list", action="store_true", help="Print available subtitles and exit")
    args = ap.parse_args()

    url = args.url
    if not url:
        try:
            url = input("YouTube URL: ").strip()
        except KeyboardInterrupt:
            return 130

    url = (url or "").replace("subtitle.to/", "").replace("Subtitle.to/", "").strip()
    try:
        url = requests.utils.unquote(url)
    except Exception:
        pass

    m = YOUTUBE_RE.match(url)
    if not m:
        print(f"not a supported youtube url: {url}", file=sys.stderr)
        return 2

    video_id = m.group(1)
    enc_id = encode_cryptojs_aes_json(video_id, DEFAULT_KEY)
    if not enc_id:
        print("failed to encode video id", file=sys.stderr)
        return 2

    sess = requests.Session()
    sess.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json,text/plain,*/*",
            "Origin": "https://downsub.com",
            "Referer": "https://downsub.com/",
        }
    )

    info = get_info_with_retry(enc_id, sess, retries=12)

    if args.list:
        print(json.dumps({"title": info.get("title"), "subtitles": info.get("subtitles"), "autoTransCount": len(info.get("subtitlesAutoTrans") or [])}, ensure_ascii=False, indent=2))
        return 0

    picked = pick_subtitle(info, args.lang)
    if not picked:
        print("no subtitles found", file=sys.stderr)
        return 1

    url_subtitle = info.get("urlSubtitle")
    if not url_subtitle:
        print("missing urlSubtitle", file=sys.stderr)
        return 1

    title = info.get("title") or "subtitle"
    title_safe = safe_filename(title)
    token = picked.get("url")
    if not token:
        print("subtitle item missing url token", file=sys.stderr)
        return 1

    download_url = f"{url_subtitle}?title={quote(title_safe)}&url={token}"

    # Follow 301/302 to download.subtitle.to and fetch the file content.
    r = sess.get(download_url, allow_redirects=True, timeout=60)
    r.raise_for_status()

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    ext = guess_ext(r.headers.get("Content-Type", ""))
    out_path = os.path.join(out_dir, f"{title_safe}_{picked.get('code') or 'unknown'}{ext}")
    with open(out_path, "wb") as f:
        f.write(r.content)

    print(
        json.dumps(
            {
                "title": title,
                "picked": {"name": picked.get("name"), "code": picked.get("code")},
                "savedTo": out_path,
                "bytes": len(r.content),
                "via": download_url,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
