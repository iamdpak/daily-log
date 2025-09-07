#!/usr/bin/env python3
import io
from pathlib import Path
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
from googleapiclient.errors import HttpError

SCOPES = ["https://www.googleapis.com/auth/drive.appdata"]
TOKEN = Path.home() / ".daily_checkin_drive" / "token.json"
OUTDIR = Path(__file__).resolve().parent / "downloads"

def drive_service():
    return build("drive", "v3", credentials=Credentials.from_authorized_user_file(TOKEN, SCOPES))

def list_appdata_files(svc):
    resp = svc.files().list(
        q="'appDataFolder' in parents and mimeType='application/octet-stream'",
        spaces="appDataFolder",
        fields="files(id,name,modifiedTime),nextPageToken",
        orderBy="name desc"
    ).execute()
    return resp.get("files", [])

def download_file(svc, file_id: str, dest: Path) -> int:
    request = svc.files().get_media(fileId=file_id)
    buf = io.BytesIO()
    downloader = MediaIoBaseDownload(buf, request)
    done = False
    while not done:
        _status, done = downloader.next_chunk()
    data = buf.getvalue()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return len(data)

def main():
    print(f"Using token: {TOKEN}")
    svc = drive_service()
    files = list_appdata_files(svc)
    if not files:
        print("No files found in AppDataFolder.")
        return

    print(f"Found {len(files)} file(s). Downloading to: {OUTDIR}")
    for f in files:
        name = f["name"]
        fid = f["id"]
        mtime = f.get("modifiedTime", "")
        dest = OUTDIR / name
        try:
            size = download_file(svc, fid, dest)
            print(f"{name}  ({mtime})  id={fid}")
            print(f"  -> saved {size} bytes to {dest}")
        except HttpError as e:
            print(f"  !! HTTP error downloading {name}: {e}")
        except Exception as e:
            print(f"  !! Error downloading {name}: {e}")

if __name__ == "__main__":
    main()
