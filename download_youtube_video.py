#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Download YouTube video with the highest available resolution (bestvideo+bestaudio).

This uses yt-dlp.

Usage:
  python download_youtube_video.py "<youtube_url>" [--out .\\videos] [--proxy http://127.0.0.1:7897] [--info-only]

Notes:
- For true highest quality, yt-dlp usually downloads video+audio separately and then merges them.
  Merging requires ffmpeg. If ffmpeg is not installed, you may end up with separate files.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys


def _configure_stdio_utf8() -> None:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _require_ytdlp():
    try:
        import yt_dlp  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "Missing dependency: yt-dlp\n"
            "Install it with: python -m pip install -r requirements.txt"
        ) from e
    return yt_dlp


def main() -> int:
    _configure_stdio_utf8()

    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?", help="YouTube URL")
    ap.add_argument("--out", default="videos", help="Output directory (default: ./videos)")
    ap.add_argument("--proxy", default=None, help="Proxy URL, e.g. http://127.0.0.1:7897")
    ap.add_argument(
        "--format",
        dest="fmt",
        default=None,
        help='yt-dlp format string (advanced). Example: "best[height<=720]"',
    )
    ap.add_argument(
        "--require-ffmpeg",
        action="store_true",
        help="Fail if ffmpeg is not installed (required for bestvideo+bestaudio merge).",
    )
    ap.add_argument("--info-only", action="store_true", help="Only print video info, do not download")
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

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    yt_dlp = _require_ytdlp()

    ffmpeg_ok = bool(shutil.which("ffmpeg"))
    if args.require_ffmpeg and not ffmpeg_ok:
        print("ffmpeg not found. Install ffmpeg or run without --require-ffmpeg.", file=sys.stderr)
        return 2

    # Highest quality: bestvideo+bestaudio (requires ffmpeg to merge).
    # Without ffmpeg, fallback to a single progressive stream (best) so it still works.
    ydl_opts = {
        "outtmpl": os.path.join(out_dir, "%(title)s.%(ext)s"),
        "noplaylist": True,
        "format": "bv*+ba/b" if ffmpeg_ok else "best",
        "quiet": False,
        "no_warnings": True,
    }
    if args.fmt:
        ydl_opts["format"] = args.fmt
    if args.proxy:
        ydl_opts["proxy"] = args.proxy
    if ffmpeg_ok:
        ydl_opts["merge_output_format"] = "mp4"

    if args.info_only:
        ydl_opts["skip_download"] = True

    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(url, download=not args.info_only)

    if args.info_only and isinstance(info, dict):
        title = info.get("title")
        webpage_url = info.get("webpage_url")
        duration = info.get("duration")
        print({"title": title, "url": webpage_url, "duration": duration, "ffmpeg": ffmpeg_ok})
        return 0

    if not ffmpeg_ok and not args.fmt:
        print(
            "Note: ffmpeg not found. Downloaded 'best' single-file stream. "
            "Install ffmpeg to enable true highest quality (bestvideo+bestaudio).",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        pass
