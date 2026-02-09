#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Download video + subtitles in parallel (single URL input).

Behavior:
- Prompt/paste YouTube URL once
- Start video download in the background
- Show interactive subtitle track list (Up/Down, Enter)
- Download the chosen subtitle
- Wait for video download to finish

Usage:
  python download_youtube_parallel.py
  python download_youtube_parallel.py "<youtube_url>"

Options:
  --sub-out ./dl
  --video-out ./videos
  --proxy http://127.0.0.1:7897
  --no-ui           (no interactive subtitle picker; auto pick first)
  --lang zh-CN      (choose subtitle by code/name, disables picker)
  --curl-fallback   (subtitle download fallback to curl.exe on SSL issues)
  --retries 12
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import threading
import time
from typing import Any


def _configure_stdio_utf8() -> None:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _download_video_bg(url: str, out_dir: str, proxy: str | None, result: dict[str, Any]) -> None:
    """
    Run yt-dlp in background thread. Keep output quiet so it doesn't break subtitle UI.
    """
    try:
        import yt_dlp  # type: ignore

        ffmpeg_ok = bool(shutil.which("ffmpeg"))
        # Keep output quiet to avoid breaking the interactive subtitle UI.
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


class _SilentLogger:
    def debug(self, msg):
        pass

    def warning(self, msg):
        pass

    def error(self, msg):
        pass


def main() -> int:
    _configure_stdio_utf8()

    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?", help="YouTube URL")
    ap.add_argument("--sub-out", default="dl", help="Subtitle output dir (default: ./dl)")
    ap.add_argument("--video-out", default="videos", help="Video output dir (default: ./videos)")
    ap.add_argument("--proxy", default=None, help="Proxy for video download (yt-dlp), e.g. http://127.0.0.1:7897")
    ap.add_argument("--lang", default=None, help="Subtitle code/name (disables picker)")
    ap.add_argument("--no-ui", action="store_true", help="Disable interactive subtitle picker")
    ap.add_argument("--curl-fallback", action="store_true", help="Subtitle download fallback to curl.exe on SSL issues")
    ap.add_argument("--retries", type=int, default=12, help="Retry attempts for subtitle get-info/download (default: 12)")
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
    t = threading.Thread(
        target=_download_video_bg,
        args=(url, video_out, args.proxy, vid_result),
        daemon=True,
    )
    t.start()
    print(f"[{time.time() - t0:6.2f}s] Video download started in background: {video_out}")

    # Subtitle flow (reuse repo implementation).
    import get_youtube_subtitle as sub
    print(f"[{time.time() - t0:6.2f}s] Fetching subtitle list...")

    # Build a session similar to CLI behavior.
    sess = sub.requests.Session()
    sess.trust_env = False  # avoid flaky system proxy by default
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

    # Parse video id and fetch track list.
    raw = url.replace("subtitle.to/", "").replace("Subtitle.to/", "").strip()
    try:
        raw = sub.requests.utils.unquote(raw)
    except Exception:
        pass

    m = sub.YOUTUBE_RE.match(raw)
    if not m:
        print(f"not a supported youtube url: {raw}", file=sys.stderr)
        return 2

    video_id = m.group(1)
    enc_id = sub.encode_cryptojs_aes_json(video_id, sub.DEFAULT_KEY)
    info = sub.get_info_with_retry(enc_id, sess, retries=max(1, int(args.retries)))
    title = info.get("title") or "subtitle"
    print(f"[{time.time() - t0:6.2f}s] Subtitle list ready: {title}")

    picked = None
    if args.lang:
        picked = sub.pick_subtitle(info, args.lang)
    else:
        tracks = sub._build_tracks(info)
        if (not args.no_ui) and sys.stdin.isatty():
            picked = sub._interactive_pick_track(tracks, title)
        else:
            picked = tracks[0] if tracks else None

    if not picked:
        print("no subtitles found or cancelled", file=sys.stderr)
        return 1

    url_subtitle = info.get("urlSubtitle")
    if not url_subtitle:
        print("missing urlSubtitle", file=sys.stderr)
        return 1

    title_safe = sub.safe_filename(title)
    token = picked.get("url")
    if not token:
        print("subtitle item missing url token", file=sys.stderr)
        return 1

    download_url = f"{url_subtitle}?title={sub.quote(title_safe)}&url={token}"

    # Download subtitle (with optional curl fallback).
    print(f"[{time.time() - t0:6.2f}s] Downloading subtitle: {picked.get('name')} ({picked.get('code')})")
    sub_path = os.path.join(sub_out, f"{title_safe}_{picked.get('code') or 'unknown'}.srt")
    try:
        r = sub._download_with_requests(sess, download_url, retries=max(1, min(12, int(args.retries))))
        ext = sub.guess_ext(r.headers.get("Content-Type", ""))
        sub_path = os.path.join(sub_out, f"{title_safe}_{picked.get('code') or 'unknown'}{ext}")
        with open(sub_path, "wb") as f:
            f.write(r.content)
        sub_ok = True
        sub_bytes = len(r.content)
        sub_note = "downloaded via requests"
    except Exception as e:
        if not args.curl_fallback:
            raise
        sub._download_with_curl(download_url, sub_path)
        sub_ok = True
        sub_bytes = os.path.getsize(sub_path)
        sub_note = "downloaded via curl fallback"

    # Wait video.
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
