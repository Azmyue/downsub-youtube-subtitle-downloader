# downsub-youtube-subtitle-downloader

Paste a YouTube link and download subtitles automatically (no clicking).

This project replicates DownSub's client-side flow (for subtitles):
1. Extract YouTube `videoId` from the URL.
2. Encrypt the `videoId` exactly like DownSub (CryptoJS AES + custom JSON format + their base64 wrapper).
3. Call `https://get-info.downsub.com/<encrypted_id>` to get subtitle tracks and `urlSubtitle`.
4. Download the subtitle file from `urlSubtitle` (it redirects to `download.subtitle.to`).

## Requirements

- Python 3.10+ (Windows/macOS/Linux)

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Usage

Single entrypoint (video + subtitle in parallel):

```powershell
python .\\download_youtube_parallel.py
```

It will:
- Start downloading the YouTube video in the background (highest quality; uses `yt-dlp`)
- Fetch subtitle tracks from DownSub
- Let you pick a subtitle track (Up/Down + Enter), or pick by `--lang`
- Download the subtitle to `./srt` and the video to `./videos`

If you see `SSL: UNEXPECTED_EOF_WHILE_READING` on Windows, it's usually caused by a local/system proxy.
By default the script bypasses system proxy settings. If you really need the system proxy, run with:

```powershell
python .\\download_youtube_parallel.py --use-system-proxy
```

If downloading still fails due to SSL/network flakiness on Windows, you can enable a fallback that uses `curl.exe`:

```powershell
python .\\download_youtube_parallel.py --curl-fallback
```

One-liner (no interactive UI):

```powershell
python .\\download_youtube_parallel.py \"https://youtu.be/RVyjM5YBF9Q\" --no-ui --lang zh-CN --curl-fallback --retries 4
```

If you need a proxy for the video download (yt-dlp), use `--proxy`:

```powershell
python .\\download_youtube_parallel.py \"https://youtu.be/RVyjM5YBF9Q\" --proxy http://127.0.0.1:7897
```

Notes:
- `--proxy` currently applies to video download only (subtitle requests default to bypassing system proxy for stability).
- For best video quality, installing `ffmpeg` is recommended so yt-dlp can merge separate video/audio streams.

## Notes

- DownSub's `get-info.downsub.com` often returns transient `503/429`. The script retries with backoff.
- Output is saved to `./srt` (subtitles) and `./videos` (video) by default.

