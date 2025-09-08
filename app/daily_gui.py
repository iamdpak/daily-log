#!/usr/bin/env python3
"""
Daily Check-in (GUI with Password / Check-in / Viewer tabs)
- Password tab: set the encryption passphrase for this session
- Check-in tab: write entry -> encrypt -> upload to Google Drive AppDataFolder
- Viewer tab: pick a date -> download -> decrypt -> list entries
- Crypto: Argon2id (KDF) + NaCl SecretBox (PyNaCl)
"""

from __future__ import annotations
import io
import json
import logging
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import List, Optional

# GUI
import tkinter as tk
from tkinter import ttk, messagebox
from tkcalendar import DateEntry

# Timezone
from zoneinfo import ZoneInfo

# Google Drive
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
from googleapiclient.errors import HttpError

# Crypto
from nacl import secret, utils
from nacl.pwhash import argon2id


# --------------------------
# Config
# --------------------------

@dataclass(frozen=True)
class AppConfig:
    app_dir: Path = Path.home() / ".daily_checkin_drive"
    # Adjust this path to where your credentials.json lives.
    # Example for repo layout:   REPO/
    #   ├─ app/daily_gui.py
    #   └─ .secrets/credentials.json
    creds_path: Path = (Path(__file__).resolve().parent.parent / ".secrets" / "credentials.json")
    token_path: Path = app_dir / "token.json"
    salt_path: Path = app_dir / "kdf_salt.bin"
    stamp_path: Path = app_dir / "last_submit_date.txt"
    scopes: tuple = ("https://www.googleapis.com/auth/drive.appdata",)
    timezone: str = "Australia/Sydney"


# --------------------------
# Crypto
# --------------------------

class CryptoManager:
    """Password-based key derivation and symmetric encryption/decryption."""
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.cfg.app_dir.mkdir(parents=True, exist_ok=True)

    def _ensure_salt(self) -> bytes:
        if not self.cfg.salt_path.exists():
            self.cfg.salt_path.write_bytes(utils.random(argon2id.SALTBYTES))
        return self.cfg.salt_path.read_bytes()

    @staticmethod
    def _kdf(passphrase: str, salt: bytes) -> bytes:
        return argon2id.kdf(
            secret.SecretBox.KEY_SIZE,
            passphrase.encode("utf-8"),
            salt,
            opslimit=argon2id.OPSLIMIT_MODERATE,
            memlimit=argon2id.MEMLIMIT_MODERATE,
        )

    def encrypt_payload(self, passphrase: str, payload: dict) -> bytes:
        salt = self._ensure_salt()
        key = self._kdf(passphrase, salt)
        box = secret.SecretBox(key)
        nonce = utils.random(secret.SecretBox.NONCE_SIZE)
        pt = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        ct = box.encrypt(pt, nonce)  # nonce + ct + mac
        # Pack: b'v1' + salt + (nonce+ct+mac)
        return b"v1" + salt + ct

    @staticmethod
    def decrypt_blob(passphrase: str, blob: bytes) -> dict:
        if len(blob) < 2 + argon2id.SALTBYTES + secret.SecretBox.NONCE_SIZE + 1:
            raise ValueError("Ciphertext too short or corrupted.")
        if blob[:2] != b"v1":
            raise ValueError("Unknown blob version (expected 'v1').")
        salt = blob[2:2 + argon2id.SALTBYTES]
        ct = blob[2 + argon2id.SALTBYTES:]
        key = CryptoManager._kdf(passphrase, salt)
        box = secret.SecretBox(key)
        pt = box.decrypt(ct)
        return json.loads(pt.decode("utf-8"))


# --------------------------
# Google Drive client
# --------------------------

class DriveClient:
    """Minimal wrapper for Google Drive AppDataFolder."""
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self._service = None

    def _ensure_auth(self):
        self.cfg.app_dir.mkdir(parents=True, exist_ok=True)
        creds: Optional[Credentials] = None
        if self.cfg.token_path.exists():
            creds = Credentials.from_authorized_user_file(str(self.cfg.token_path), self.cfg.scopes)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                from google.auth.transport.requests import Request
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(str(self.cfg.creds_path), self.cfg.scopes)
                # Desktop flow – opens browser
                creds = flow.run_local_server(port=0)
            self.cfg.token_path.write_text(creds.to_json())
        self._service = build("drive", "v3", credentials=creds)

    @property
    def service(self):
        if self._service is None:
            self._ensure_auth()
        return self._service

    def upload_appdata(self, name: str, content: bytes) -> dict:
        media = MediaIoBaseUpload(io.BytesIO(content), mimetype="application/octet-stream")
        meta = {"name": name, "parents": ["appDataFolder"], "mimeType": "application/octet-stream"}
        return self.service.files().create(body=meta, media_body=media, fields="id,name").execute()

    def list_appdata(self) -> List[dict]:
        q = "'appDataFolder' in parents and mimeType='application/octet-stream'"
        items: List[dict] = []
        token = None
        while True:
            resp = self.service.files().list(
                q=q,
                spaces="appDataFolder",
                fields="files(id,name,modifiedTime),nextPageToken",
                orderBy="name desc",
                pageToken=token
            ).execute()
            items += resp.get("files", [])
            token = resp.get("nextPageToken")
            if not token:
                break
        return items

    def download(self, file_id: str) -> bytes:
        """Robust, chunked download with clear error messages."""
        request = self.service.files().get_media(fileId=file_id)
        buf = io.BytesIO()
        downloader = MediaIoBaseDownload(buf, request)
        done = False
        try:
            while not done:
                _status, done = downloader.next_chunk()
            return buf.getvalue()
        except HttpError as e:
            msg = getattr(e, "reason", None) or str(e)
            raise RuntimeError(f"Drive download failed: {msg}")


# --------------------------
# Stamp (one-per-day)
# --------------------------

class StampStore:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg

    def write_today(self):
        self.cfg.stamp_path.write_text(date.today().isoformat(), encoding="utf-8")

    def submitted_today(self) -> bool:
        try:
            return self.cfg.stamp_path.read_text(encoding="utf-8").strip() == date.today().isoformat()
        except FileNotFoundError:
            return False


# --------------------------
# Controller
# --------------------------

class DailyController:
    """Orchestrates crypto + drive + stamp logic."""
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.crypto = CryptoManager(cfg)
        self.drive = DriveClient(cfg)
        self.stamp = StampStore(cfg)
        self.tz = ZoneInfo(cfg.timezone)

    def submit_entry(self, passphrase: str, text: str) -> str:
        if not text.strip():
            raise ValueError("Entry is empty.")
        if not passphrase:
            raise ValueError("Password is required.")

        payload = {
            "ts_local": datetime.now(self.tz).isoformat(timespec="seconds"),
            "entry": text.strip(),
        }
        blob = self.crypto.encrypt_payload(passphrase, payload)
        ymd = date.today().isoformat()
        name = f"{ymd}.json.enc"
        self.drive.upload_appdata(name, blob)
        self.stamp.write_today()
        return name

    def load_entries_for_date(self, passphrase: str, target: date) -> List[tuple[str, str]]:
        """Return [(HH:MM, text), ...] for the given date. Handles both single and array payloads."""
        if not passphrase:
            raise ValueError("Password is required to view entries.")

        ymd = target.isoformat()
        files = [f for f in self.drive.list_appdata() if f["name"].startswith(ymd)]
        out: List[tuple[str, str]] = []
        for f in sorted(files, key=lambda x: x["name"]):
            blob = self.drive.download(f["id"])
            obj = self.crypto.decrypt_blob(passphrase, blob)

            # Normalize payloads
            items = obj["entries"] if isinstance(obj, dict) and isinstance(obj.get("entries"), list) else [obj]

            for it in items:
                txt = (it.get("entry") or "").strip()
                ts = it.get("ts_local") or f.get("modifiedTime")
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(self.tz)
                    hhmm = dt.strftime("%H:%M")
                except Exception:
                    hhmm = "—"
                if txt:
                    out.append((hhmm, txt))
        # Sort within day
        out.sort(key=lambda x: x[0])
        return out


# --------------------------
# GUI (Tk)
# --------------------------

log = logging.getLogger("daily")
logging.basicConfig(level=logging.INFO)

class DailyApp(tk.Tk):
    def __init__(self, controller: DailyController):
        super().__init__()
        self.ctrl = controller

        # Window
        self.title("Daily Check-in")
        self.geometry("680x540")
        self.minsize(600, 480)

        # Shared state
        self.passphrase = tk.StringVar()
        self.status_var = tk.StringVar()
        self.viewer_status = tk.StringVar()

        # Tabs
        nb = ttk.Notebook(self)
        self.tab_password = ttk.Frame(nb)
        self.tab_checkin  = ttk.Frame(nb)
        self.tab_viewer   = ttk.Frame(nb)
        nb.add(self.tab_password, text="Password")
        nb.add(self.tab_checkin,  text="Check-in")
        nb.add(self.tab_viewer,   text="Viewer")
        nb.pack(expand=True, fill=tk.BOTH)

        self._build_password_tab()
        self._build_checkin_tab()
        self._build_viewer_tab()

    # ---- Tab builders ----
    def _build_password_tab(self):
        frm = self.tab_password
        ttk.Label(frm, text="Encryption password for this session").pack(anchor="w", padx=10, pady=(12, 6))

        row = ttk.Frame(frm); row.pack(fill=tk.X, padx=10, pady=(0, 10))
        ttk.Label(row, text="Password:").pack(side=tk.LEFT)
        ttk.Entry(row, show="*", textvariable=self.passphrase, width=30).pack(side=tk.LEFT, padx=(6, 12))

        info = ("This password is used to encrypt new entries (Check-in tab)\n"
                "and to decrypt saved entries (Viewer tab).")
        ttk.Label(frm, text=info, foreground="gray").pack(anchor="w", padx=10)

        # Optional convenience actions
        btns = ttk.Frame(frm); btns.pack(anchor="w", padx=10, pady=8)
        ttk.Button(btns, text="Clear password", command=lambda: self.passphrase.set("")).pack(side=tk.LEFT)

    def _build_checkin_tab(self):
        frm = self.tab_checkin
        ttk.Label(frm, text="What did you do today?").pack(anchor="w", padx=10, pady=(12, 4))
        self.txt = tk.Text(frm, wrap="word", height=14)
        self.txt.pack(expand=True, fill=tk.BOTH, padx=10)

        row = ttk.Frame(frm); row.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(row, text="Submit", command=self._on_submit).pack(side=tk.LEFT)

        ttk.Label(frm, textvariable=self.status_var, foreground="green").pack(anchor="w", padx=10, pady=(0, 12))

    def _build_viewer_tab(self):
        frm = self.tab_viewer
        top = ttk.Frame(frm); top.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(top, text="Select date:").pack(side=tk.LEFT)
        self.date_picker = DateEntry(top, date_pattern="yyyy-mm-dd")
        self.date_picker.set_date(date.today())
        self.date_picker.pack(side=tk.LEFT, padx=8)

        ttk.Button(top, text="Load", command=self._on_load_day).pack(side=tk.LEFT)
        ttk.Label(top, textvariable=self.viewer_status, foreground="gray").pack(side=tk.LEFT, padx=12)

        self.listbox = tk.Listbox(frm)
        self.listbox.pack(expand=True, fill=tk.BOTH, padx=10, pady=(0, 10))

    # ---- Actions ----
    def _on_submit(self):
        entry = self.txt.get("1.0", tk.END).strip()
        pw = self.passphrase.get().strip()
        if not pw:
            self.status_var.set("Set your encryption password on the Password tab first.")
            return
        try:
            saved_as = self.ctrl.submit_entry(pw, entry)
            self.status_var.set(f"Saved (encrypted) to Drive as {saved_as}")
            self.txt.delete("1.0", tk.END)
        except Exception as e:
            self.status_var.set(f"Failed: {e}")

    def _on_load_day(self):
        pw = self.passphrase.get().strip()
        if not pw:
            messagebox.showinfo("Password needed", "Go to the Password tab and enter your encryption password.")
            return

        target = self.date_picker.get_date()
        self.listbox.delete(0, tk.END)
        self.viewer_status.set("Loading…")
        self.update_idletasks()

        try:
            # TEMP logging to see what the app sees
            files = self.ctrl.drive.list_appdata()
            for f in files[:8]:
                log.info("AppData: %s (%s) id=%s", f["name"], f.get("modifiedTime",""), f["id"])

            rows = self.ctrl.load_entries_for_date(pw, target)
            if not rows:
                self.viewer_status.set("No entries for that date.")
                return
            for hhmm, text in rows:
                self.listbox.insert(tk.END, f"[{hhmm}] {text}")
            self.viewer_status.set(f"Loaded {len(rows)} entr{'y' if len(rows)==1 else 'ies'}.")
        except RuntimeError as e:  # from Drive download
            self.viewer_status.set(str(e))
        except HttpError as e:
            self.viewer_status.set(f"HTTP error: {e}")
        except Exception as e:
            self.viewer_status.set(f"Failed: {e}")


# --------------------------
# Main
# --------------------------

def main():
    cfg = AppConfig()
    # Debug prints once (helpful if paths are wrong); comment out later.
    print("creds_path:", cfg.creds_path)
    print("token_path:", cfg.token_path)
    app = DailyApp(DailyController(cfg))
    app.mainloop()

if __name__ == "__main__":
    main()
