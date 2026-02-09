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

## Notes

- DownSub's `get-info.downsub.com` often returns transient `503/429`. The script retries with backoff.
- Output is saved to `./dl` by default.

