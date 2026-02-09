#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Single-file entrypoint: download video + subtitles in parallel (one URL input).

Behavior:
- Prompt/paste YouTube URL once
- Start video download in the background (yt-dlp)
- Show interactive subtitle track list (Up/Down, Enter) unless --no-ui or --lang is provided
- Download the chosen subtitle
- Wait for video download to finish

Usage:
  python download_youtube_parallel.py
  python download_youtube_parallel.py "<youtube_url>"

Options:
  --sub-out ./srt
  --video-out ./videos
  --proxy http://127.0.0.1:7897   (video download proxy)
  --no-ui
  --lang zh-CN
  --curl-fallback
  --retries 12
  --use-system-proxy             (subtitle HTTP: use Windows/system proxy)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.parse import quote


DEFAULT_KEY = "zthxw34cdp6wfyxmpad38v52t3hsz6c5"

YOUTUBE_RE = re.compile(
    r"^(?:http(?:s)?:\/\/)?(?:www\.)?(?:m\.)?"
    r"(?:youtu\.be\/|youtube\.com\/(?:(?:watch|live)?\?(?:.*&)?v(?:i)?=|(?:embed|v|vi|user|shorts|live)\/))"
    r'([^\?&"\'>]+)'
    r"(?:(?:&|.+)?list=([a-zA-Z0-9_-]+))?"
)


def _configure_stdio_utf8() -> None:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


class _SilentLogger:
    def debug(self, msg):
        pass

    def warning(self, msg):
        pass

    def error(self, msg):
        pass


def _download_video_bg(url: str, out_dir: str, proxy: str | None, result: dict[str, Any]) -> None:
    # Run yt-dlp in background thread. Keep output quiet so it doesn't break subtitle UI.
    try:
        import yt_dlp  # type: ignore

        ffmpeg_ok = bool(shutil.which("ffmpeg"))
        ydl_opts: dict[str, Any] = {
            "outtmpl": os.path.join(out_dir, "%(title)s.%(ext)s"),
            "noplaylist": True,
            "format": "bv*+ba/b" if ffmpeg_ok else "best",
            "quiet": True,
            "no_warnings": True,
            "noprogress": True,
            "logger": _SilentLogger(),
        }
        if proxy:
            ydl_opts["proxy"] = proxy
        if ffmpeg_ok:
            ydl_opts["merge_output_format"] = "mp4"

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)

        result["ok"] = True
        result["title"] = (info or {}).get("title")
        result["ffmpeg"] = ffmpeg_ok
        result["out_dir"] = out_dir
    except Exception as e:
        result["ok"] = False
        result["error"] = str(e)


def _evp_bytes_to_key_md5(password: bytes, salt8: bytes, key_len: int, iv_len: int) -> tuple[bytes, bytes]:
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
    # DownSub bundle Pt(): single replacements only
    b64 = base64.b64encode(s.encode("utf-8")).decode("ascii")
    b64 = b64.replace("+", "-", 1)
    b64 = b64.replace("/", "_", 1)
    b64 = b64.replace("=", "", 1)
    return b64.strip()


def encode_cryptojs_aes_json(data_obj, key: str = DEFAULT_KEY) -> str:
    from Crypto.Cipher import AES  # pycryptodome

    if data_obj is None or data_obj == "":
        return ""

    plaintext = json.dumps(data_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    salt8 = os.urandom(8)
    key_bytes, iv = _evp_bytes_to_key_md5(key.encode("utf-8"), salt8, 32, 16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(_pkcs7_pad(plaintext, 16))

    mt = {"ct": base64.b64encode(ct).decode("ascii"), "iv": iv.hex(), "s": salt8.hex()}
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


def get_info_with_retry(enc_id: str, session, retries: int = 12) -> dict:
    import requests

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
        except (requests.exceptions.SSLError, requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            if i == retries - 1:
                raise
            delay = min(8.0, 0.7 * (2**i)) + random.random() * 0.3
            time.sleep(delay)
            continue

        if r.status_code == 200 and isinstance(data, dict) and "subtitles" in data:
            return data

        if r.status_code == 503 and isinstance(data, dict) and "error" in data:
            msg = str(data.get("error") or "")
            if "Video not found or unavailable" in msg:
                time.sleep(1.0 + random.random() * 0.2)
                continue

        if r.status_code == 429 or (500 <= r.status_code <= 599):
            delay = min(8.0, 0.7 * (2**i)) + random.random() * 0.3
            time.sleep(delay)
            continue

        raise RuntimeError(f"get-info failed: {r.status_code} {data}")

    raise RuntimeError(f"get-info failed after retries: {getattr(last, 'status_code', None)}")


def _download_with_requests(session, url: str, retries: int = 6):
    import requests

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
            tracks.append({"group": "original", "name": x.get("name") or "", "code": x.get("code") or "", "url": x.get("url")})
    for x in info.get("subtitlesAutoTrans") or []:
        if isinstance(x, dict) and x.get("url"):
            tracks.append({"group": "auto", "name": x.get("name") or "", "code": x.get("code") or "", "url": x.get("url")})
    return tracks


def _interactive_pick_track(tracks: list[dict], title: str) -> dict | None:
    if not tracks:
        return None
    try:
        import msvcrt  # type: ignore
    except Exception:
        return None

    idx = 0
    offset = 0

    def term_height() -> int:
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
            if key == "H":
                idx = (idx - 1) % len(tracks)
                render()
            elif key == "P":
                idx = (idx + 1) % len(tracks)
                render()
            elif key == "G":
                idx = 0
                render()
            elif key == "O":
                idx = len(tracks) - 1
                render()


def _pick_by_lang(tracks: list[dict], lang: str) -> dict | None:
    for t in tracks:
        if t.get("code") == lang or t.get("name") == lang:
            return t
    return None


def main() -> int:
    _configure_stdio_utf8()

    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?", help="YouTube URL")
    ap.add_argument("--sub-out", default="srt", help="Subtitle output dir (default: ./srt)")
    ap.add_argument("--video-out", default="videos", help="Video output dir (default: ./videos)")
    ap.add_argument("--proxy", default=None, help="Proxy for video download (yt-dlp), e.g. http://127.0.0.1:7897")
    ap.add_argument("--lang", default=None, help="Subtitle code/name (disables picker)")
    ap.add_argument("--no-ui", action="store_true", help="Disable interactive subtitle picker")
    ap.add_argument("--curl-fallback", action="store_true", help="Subtitle download fallback to curl.exe on SSL issues")
    ap.add_argument("--retries", type=int, default=12, help="Retry attempts for subtitle get-info/download (default: 12)")
    ap.add_argument("--use-system-proxy", action="store_true", help="Use Windows/system proxy for subtitle HTTP (default: off)")
    args = ap.parse_args()

    url = args.url
    if not url:
        try:
            url = input("YouTube URL: ").strip()
        except KeyboardInterrupt:
            return 130
    if not url:
        print("Missing URL", file=sys.stderr)
        return 2

    sub_out = os.path.abspath(args.sub_out)
    video_out = os.path.abspath(args.video_out)
    os.makedirs(sub_out, exist_ok=True)
    os.makedirs(video_out, exist_ok=True)

    t0 = time.time()

    # Start video download in background.
    vid_result: dict[str, Any] = {}
    t = threading.Thread(target=_download_video_bg, args=(url, video_out, args.proxy, vid_result), daemon=True)
    t.start()
    print(f"[{time.time() - t0:6.2f}s] Video download started in background: {video_out}")

    import requests

    print(f"[{time.time() - t0:6.2f}s] Fetching subtitle list...")
    sess = requests.Session()
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

    raw = url.replace("subtitle.to/", "").replace("Subtitle.to/", "").strip()
    try:
        raw = requests.utils.unquote(raw)
    except Exception:
        pass

    m = YOUTUBE_RE.match(raw)
    if not m:
        print(f"not a supported youtube url: {raw}", file=sys.stderr)
        return 2

    video_id = m.group(1)
    enc_id = encode_cryptojs_aes_json(video_id, DEFAULT_KEY)
    info = get_info_with_retry(enc_id, sess, retries=max(1, int(args.retries)))
    title = info.get("title") or "subtitle"
    print(f"[{time.time() - t0:6.2f}s] Subtitle list ready: {title}")

    tracks = _build_tracks(info)
    picked = None
    if args.lang:
        picked = _pick_by_lang(tracks, args.lang)
        if not picked and tracks:
            picked = tracks[0]
    else:
        if (not args.no_ui) and sys.stdin.isatty():
            picked = _interactive_pick_track(tracks, title)
        else:
            picked = tracks[0] if tracks else None

    if not picked:
        print("no subtitles found or cancelled", file=sys.stderr)
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

    print(f"[{time.time() - t0:6.2f}s] Downloading subtitle: {picked.get('name')} ({picked.get('code')})")
    sub_path = os.path.join(sub_out, f"{title_safe}_{picked.get('code') or 'unknown'}.srt")
    try:
        r = _download_with_requests(sess, download_url, retries=max(1, min(12, int(args.retries))))
        ext = guess_ext(r.headers.get("Content-Type", ""))
        sub_path = os.path.join(sub_out, f"{title_safe}_{picked.get('code') or 'unknown'}{ext}")
        with open(sub_path, "wb") as f:
            f.write(r.content)
        sub_ok = True
        sub_bytes = len(r.content)
        sub_note = "downloaded via requests"
    except Exception:
        if not args.curl_fallback:
            raise
        _download_with_curl(download_url, sub_path)
        sub_ok = True
        sub_bytes = os.path.getsize(sub_path)
        sub_note = "downloaded via curl fallback"

    print(f"[{time.time() - t0:6.2f}s] Subtitle done. Waiting for video download...")
    t.join()
    print(f"[{time.time() - t0:6.2f}s] Video download finished.")

    print(
        {
            "subtitle": {
                "ok": sub_ok,
                "picked": {"name": picked.get("name"), "code": picked.get("code")},
                "savedTo": sub_path,
                "bytes": sub_bytes,
                "note": sub_note,
            },
            "video": vid_result,
        }
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        pass

