# downsub-youtube-subtitle-downloader

Paste a YouTube link and download subtitles automatically (no clicking).

This project replicates DownSub's client-side flow:
1. Extract YouTube `videoId` from the URL.
2. Encrypt the `videoId` exactly like DownSub (CryptoJS AES + custom JSON format + their base64 wrapper).
3. Call `https://get-info.downsub.com/<encrypted_id>` to get subtitle tracks and `urlSubtitle`.
4. Download the subtitle file from `urlSubtitle` (it redirects to `download.subtitle.to`).

## Requirements

- Python 3.10+

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Usage

Download (interactive prompt):

```powershell
python .\\get_youtube_subtitle.py
```

If you don't pass `--lang`, an interactive list will be shown (use Up/Down, Enter to download).

If you see `SSL: UNEXPECTED_EOF_WHILE_READING` on Windows, it's usually caused by a local/system proxy.
By default the script bypasses system proxy settings. If you really need the system proxy, run with:

```powershell
python .\\get_youtube_subtitle.py --use-system-proxy
```

If downloading still fails due to SSL/network flakiness on Windows, you can enable a fallback that uses `curl.exe`:

```powershell
python .\\get_youtube_subtitle.py --curl-fallback
```

Download (one-liner):

```powershell
python .\\get_youtube_subtitle.py \"https://youtu.be/RVyjM5YBF9Q\" --lang zh --out .\\dl
```

List available subtitle tracks (no download):

```powershell
python .\\get_youtube_subtitle.py \"https://youtu.be/RVyjM5YBF9Q\" --list
```

Windows helper (PowerShell):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\\download_youtube_sub.ps1
```

## Download Video (Highest Resolution)

This uses `yt-dlp` to download the highest available quality. For best quality it often needs `ffmpeg` to merge video+audio.

Download:

```powershell
python .\\download_youtube_video.py
```

One-liner:

```powershell
python .\\download_youtube_video.py \"https://youtu.be/RVyjM5YBF9Q\" --out .\\videos
```

If you need a proxy (example):

```powershell
python .\\download_youtube_video.py \"https://youtu.be/RVyjM5YBF9Q\" --proxy http://127.0.0.1:7897
```

## Notes

- DownSub's `get-info.downsub.com` often returns transient `503/429`. The script retries with backoff.
- Output is saved to `./dl` by default.

