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
import subprocess
import sys
import time
import random
import shutil
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
        try:
            r = session.get(url, timeout=30)
            last = r
            try:
                data = r.json()
            except Exception:
                data = {"raw": r.text}
        except (requests.exceptions.SSLError, requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            # Often caused by flaky local proxy / MITM / upstream. Treat as transient.
            if i == retries - 1:
                raise
            delay = min(8.0, 0.7 * (2**i)) + random.random() * 0.3
            time.sleep(delay)
            continue

        if r.status_code == 200 and isinstance(data, dict) and "subtitles" in data:
            return data

        # Transient behaviors:
        # - 503 + {"error":"Video not found or unavailable"} is often temporary on the first request.
        # - 429 / 5xx can happen due to rate limiting / upstream.
        if r.status_code == 503 and isinstance(data, dict) and "error" in data:
            msg = str(data.get("error") or "")
            if "Video not found or unavailable" in msg:
                # Fast retry helps more than long exponential delays.
                time.sleep(1.0 + random.random() * 0.2)
                continue

        if r.status_code == 429 or (500 <= r.status_code <= 599):
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


def _download_with_requests(session: requests.Session, url: str, retries: int = 6) -> requests.Response:
    last_exc = None
    for i in range(retries):
        try:
            r = session.get(url, allow_redirects=True, timeout=60)
            r.raise_for_status()
            return r
        except (requests.exceptions.SSLError, requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_exc = e
            delay = min(8.0, 0.7 * (2**i)) + random.random() * 0.3
            time.sleep(delay)
    raise RuntimeError(f"download failed after retries due to network/SSL error: {last_exc}") from last_exc


def _download_with_curl(url: str, out_path: str) -> None:
    """
    Fallback for Windows environments where Python SSL handshake is flaky.
    Uses curl.exe to follow redirects and save the file.
    """
    curl = shutil.which("curl.exe") or shutil.which("curl")
    if not curl:
        raise RuntimeError("curl.exe not found for fallback download")

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    cmd = [curl, "-sS", "-L", "-o", out_path, url]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        stderr = (p.stderr or "").strip()
        raise RuntimeError(f"curl download failed (code {p.returncode}): {stderr}")


def _build_tracks(info: dict) -> list[dict]:
    tracks: list[dict] = []
    for x in info.get("subtitles") or []:
        if isinstance(x, dict) and x.get("url"):
            tracks.append(
                {
                    "group": "original",
                    "name": x.get("name") or "",
                    "code": x.get("code") or "",
                    "url": x.get("url"),
                }
            )
    for x in info.get("subtitlesAutoTrans") or []:
        if isinstance(x, dict) and x.get("url"):
            tracks.append(
                {
                    "group": "auto",
                    "name": x.get("name") or "",
                    "code": x.get("code") or "",
                    "url": x.get("url"),
                }
            )
    return tracks


def _interactive_pick_track(tracks: list[dict], title: str) -> dict | None:
    """
    Windows-friendly interactive picker (no external deps).

    Controls:
      Up/Down: move
      Enter: select
      q / Esc: quit
    """
    if not tracks:
        return None

    try:
        import msvcrt  # type: ignore
    except Exception:
        return None

    idx = 0
    offset = 0

    def term_height() -> int:
        # Reserve a few lines for header/footer.
        h = shutil.get_terminal_size((100, 30)).lines
        return max(8, h)

    def render() -> None:
        nonlocal offset
        h = term_height()
        view_h = h - 6
        if idx < offset:
            offset = idx
        if idx >= offset + view_h:
            offset = idx - view_h + 1

        os.system("cls")
        print(f"Title: {title}")
        print("Select a subtitle track (Up/Down, Enter to download, q/Esc to quit)")
        print("-" * 80)

        end = min(len(tracks), offset + view_h)
        for i in range(offset, end):
            t = tracks[i]
            prefix = "> " if i == idx else "  "
            tag = "[O]" if t.get("group") == "original" else "[A]"
            name = t.get("name") or ""
            code = t.get("code") or ""
            line = f"{prefix}{tag} {name} ({code})"
            print(line[:78])

        print("-" * 80)
        print(f"{idx+1}/{len(tracks)}  [O]=original  [A]=auto-translated")

    render()
    while True:
        ch = msvcrt.getwch()
        if ch in ("q", "Q", "\x1b"):
            return None
        if ch == "\r":
            return tracks[idx]
        if ch in ("\x00", "\xe0"):
            key = msvcrt.getwch()
            if key == "H":  # up
                idx = (idx - 1) % len(tracks)
                render()
            elif key == "P":  # down
                idx = (idx + 1) % len(tracks)
                render()
            elif key == "G":  # home
                idx = 0
                render()
            elif key == "O":  # end
                idx = len(tracks) - 1
                render()


def _configure_stdio_utf8() -> None:
    # Avoid Windows cp936/gbk encode crashes when printing non-ASCII.
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main() -> int:
    _configure_stdio_utf8()

    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?", help="YouTube URL")
    ap.add_argument("--lang", default=None, help="Subtitle code/name, e.g. zh-CN / zh / English")
    ap.add_argument("--out", default="dl", help="Output directory (default: ./dl)")
    ap.add_argument("--list", action="store_true", help="Print available subtitles and exit")
    ap.add_argument("--retries", type=int, default=12, help="Retry attempts for get-info/download (default: 12)")
    ap.add_argument(
        "--use-system-proxy",
        action="store_true",
        help="Use system proxy settings (Windows Internet Options). Default: disabled to avoid SSL EOF issues.",
    )
    ap.add_argument(
        "--curl-fallback",
        action="store_true",
        help="If requests download fails due to SSL/network issues, fallback to curl.exe (Windows).",
    )
    ap.add_argument(
        "--no-ui",
        action="store_true",
        help="Disable interactive selection UI (auto-pick first track if --lang not provided)",
    )
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
    # Requests on Windows can pick up WinINET proxy even if env vars are empty.
    # Many local proxies (or capture tools) can cause SSL EOF; default to bypassing them.
    if not args.use_system_proxy:
        sess.trust_env = False
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

    info = get_info_with_retry(enc_id, sess, retries=max(1, int(args.retries)))

    if args.list:
        tracks = _build_tracks(info)
        print(
            json.dumps(
                {
                    "title": info.get("title"),
                    "tracks": [{"group": t["group"], "name": t["name"], "code": t["code"]} for t in tracks],
                    "count": len(tracks),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    title = info.get("title") or "subtitle"

    picked: dict | None = None
    if args.lang:
        picked = pick_subtitle(info, args.lang)
    else:
        tracks = _build_tracks(info)
        if sys.stdin.isatty() and not args.no_ui:
            picked = _interactive_pick_track(tracks, title)
        else:
            picked = tracks[0] if tracks else None

    if not picked:
        print("no subtitles found", file=sys.stderr)
        return 1

    url_subtitle = info.get("urlSubtitle")
    if not url_subtitle:
        print("missing urlSubtitle", file=sys.stderr)
        return 1

    title_safe = safe_filename(title)
    token = picked.get("url")
    if not token:
        print("subtitle item missing url token", file=sys.stderr)
        return 1

    download_url = f"{url_subtitle}?title={quote(title_safe)}&url={token}"

    # Follow 301/302 to download.subtitle.to and fetch the file content.
    try:
        r = _download_with_requests(sess, download_url, retries=max(1, min(12, int(args.retries))))
        content = r.content
        content_type = r.headers.get("Content-Type", "")
    except Exception as e:
        if not args.curl_fallback:
            raise
        # Fallback path: use curl.exe and infer extension from URL (default .srt).
        content = b""
        content_type = ""
        # Use .srt by default for curl fallback (DownSub returns .srt for most cases).
        out_dir = os.path.abspath(args.out)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"{title_safe}_{picked.get('code') or 'unknown'}.srt")
        _download_with_curl(download_url, out_path)
        size = os.path.getsize(out_path)
        print(
            json.dumps(
                {
                    "title": title,
                    "picked": {"name": picked.get("name"), "code": picked.get("code")},
                    "savedTo": out_path,
                    "bytes": size,
                    "via": download_url,
                    "note": "downloaded via curl fallback",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    ext = guess_ext(content_type)
    out_path = os.path.join(out_dir, f"{title_safe}_{picked.get('code') or 'unknown'}{ext}")
    with open(out_path, "wb") as f:
        f.write(content)

    print(
        json.dumps(
            {
                "title": title,
                "picked": {"name": picked.get("name"), "code": picked.get("code")},
                "savedTo": out_path,
                "bytes": len(content),
                "via": download_url,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        # Allow piping to tools like `Select-Object -First N` without crashing.
        pass
