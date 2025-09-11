#!/usr/bin/env python3
"""
Daily Check-in (Password / Check-in / Viewer tabs)
- Password tab: set the encryption passphrase for this session
- Check-in tab: TWO stacked text boxes (A on top, B below) with Upload buttons on the side
- Viewer tab: TWO stacked wrapped viewers (A on top, B below) with Load buttons on the side
- Storage: Google Drive AppDataFolder
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
from tkinter.scrolledtext import ScrolledText
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


log = logging.getLogger("daily")
logging.basicConfig(level=logging.INFO)

# --------------------------
# Config
# --------------------------

@dataclass(frozen=True)
class AppConfig:
    app_dir: Path = Path.home() / ".daily_checkin_drive"
    # Adjust this path to where your credentials.json lives.
    # Example repo layout:
    #   REPO/
    #     ├─ app/daily_gui.py
    #     └─ .secrets/credentials.json
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
    """Orchestrates crypto + drive + stamp logic for two categories (A/B)."""
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.crypto = CryptoManager(cfg)
        self.drive = DriveClient(cfg)
        self.stamp = StampStore(cfg)
        self.tz = ZoneInfo(cfg.timezone)

    @staticmethod
    def _fname(d: date, category: str) -> str:
        return f"{d.isoformat()}_{category}.json.enc"

    def submit_entry(self, passphrase: str, text: str, category: str) -> str:
        if not text.strip():
            raise ValueError("Entry is empty.")
        if not passphrase:
            raise ValueError("Password is required.")
        if category not in ("A", "B"):
            raise ValueError("Unknown category.")

        payload = {
            "ts_local": datetime.now(self.tz).isoformat(timespec="seconds"),
            "category": category,
            "entry": text.strip(),
        }
        blob = self.crypto.encrypt_payload(passphrase, payload)
        name = self._fname(date.today(), category)
        self.drive.upload_appdata(name, blob)
        self.stamp.write_today()
        return name

    def load_entries_for(self, passphrase: str, target: date, category: str) -> List[tuple[str, str]]:
        """Return [(HH:MM, text), ...] for the given date & category."""
        if not passphrase:
            raise ValueError("Password is required to view entries.")
        if category not in ("A", "B"):
            raise ValueError("Unknown category.")

        wanted = self._fname(target, category)
        files = [f for f in self.drive.list_appdata() if f["name"] == wanted]
        out: List[tuple[str, str]] = []
        for f in files:
            blob = self.drive.download(f["id"])
            try:
                obj = self.crypto.decrypt_blob(passphrase, blob)
            except Exception as e:
                log.warning("Failed to decrypt %s: %s", f["name"], e)
                continue


            items = obj["entries"] if isinstance(obj, dict) and isinstance(obj.get("entries"), list) else [obj]
            for it in items:
                if it.get("category") and it.get("category") != category:
                    continue
                txt = (it.get("entry") or "").strip()
                ts = it.get("ts_local") or f.get("modifiedTime")
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(self.tz)
                    hhmm = dt.strftime("%H:%M")
                except Exception:
                    hhmm = "—"
                if txt:
                    out.append((hhmm, txt))
        out.sort(key=lambda x: x[0])
        return out


# --------------------------
# GUI (Tk)
# --------------------------



class DailyApp(tk.Tk):
    def __init__(self, controller: DailyController):
        super().__init__()
        self.ctrl = controller

        # Window
        self.title("Daily Check-in (A & B)")
        self.geometry("840x750")
        self.minsize(780, 580)

        # Shared state
        self.passphrase = tk.StringVar()
        self.status_submit_A = tk.StringVar()
        self.status_submit_B = tk.StringVar()
        self.status_view_A = tk.StringVar()
        self.status_view_B = tk.StringVar()

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
        ttk.Entry(row, show="*", textvariable=self.passphrase, width=32).pack(side=tk.LEFT, padx=(6, 12))

        info = ("This password encrypts uploads (Check-in) and decrypts downloads (Viewer).")
        ttk.Label(frm, text=info, foreground="gray").pack(anchor="w", padx=10, pady=(2, 0))

        ttk.Button(frm, text="Clear password", command=lambda: self.passphrase.set("")).pack(anchor="w", padx=10, pady=10)

    def _build_checkin_tab(self):
        frm = self.tab_checkin

        # ----- Row A -----
        rowA = ttk.Frame(frm)
        rowA.pack(expand=True, fill=tk.BOTH, padx=12, pady=(12, 6))
        rowA.columnconfigure(0, weight=1)

        leftA = ttk.Frame(rowA)
        leftA.grid(row=0, column=0, sticky="nsew")
        sideA = ttk.Frame(rowA)
        sideA.grid(row=0, column=1, sticky="ns", padx=(10, 0))

        ttk.Label(leftA, text="Category A").pack(anchor="w")
        self.txt_A = ScrolledText(leftA, wrap="word", height=18, font=("TkDefaultFont", 11))
        self.txt_A.pack(expand=True, fill=tk.BOTH, pady=(4, 0))

        ttk.Button(sideA, text="Upload A", command=lambda: self._on_upload("A")).pack(fill=tk.X, pady=(4, 0))
        ttk.Label(leftA, textvariable=self.status_submit_A, foreground="green").pack(anchor="w", pady=(6, 0))

        # ----- Row B -----
        rowB = ttk.Frame(frm)
        rowB.pack(expand=True, fill=tk.BOTH, padx=12, pady=(6, 12))
        rowB.columnconfigure(0, weight=1)

        leftB = ttk.Frame(rowB)
        leftB.grid(row=0, column=0, sticky="nsew")
        sideB = ttk.Frame(rowB)
        sideB.grid(row=0, column=1, sticky="ns", padx=(10, 0))

        ttk.Label(leftB, text="Category B").pack(anchor="w")
        self.txt_B = ScrolledText(leftB, wrap="word", height=18, font=("TkDefaultFont", 11))
        self.txt_B.pack(expand=True, fill=tk.BOTH, pady=(4, 0))

        ttk.Button(sideB, text="Upload B", command=lambda: self._on_upload("B")).pack(fill=tk.X, pady=(4, 0))
        ttk.Label(leftB, textvariable=self.status_submit_B, foreground="green").pack(anchor="w", pady=(6, 0))


    def _build_viewer_tab(self):
        frm = self.tab_viewer

        # Date picker top bar
        top = ttk.Frame(frm)
        top.pack(fill=tk.X, padx=12, pady=10)
        ttk.Label(top, text="Select date:").pack(side=tk.LEFT)
        self.date_picker = DateEntry(top, date_pattern="yyyy-mm-dd")
        self.date_picker.set_date(date.today())
        self.date_picker.pack(side=tk.LEFT, padx=8)

        # ----- Viewer A -----
        rowA = ttk.Frame(frm)
        rowA.pack(expand=True, fill=tk.BOTH, padx=12, pady=(0, 6))
        rowA.columnconfigure(0, weight=1)

        leftA = ttk.Frame(rowA)
        leftA.grid(row=0, column=0, sticky="nsew")
        sideA = ttk.Frame(rowA)
        sideA.grid(row=0, column=1, sticky="ns", padx=(10, 0))

        ttk.Label(leftA, text="Category A").pack(anchor="w")
        self.viewer_A = ScrolledText(leftA, wrap="word", height=18, font=("TkDefaultFont", 11))
        self.viewer_A.pack(expand=True, fill=tk.BOTH, pady=(4, 0))
        self.viewer_A.config(state=tk.DISABLED)

        ttk.Button(sideA, text="Load A", command=lambda: self._on_load("A")).pack(fill=tk.X, pady=(4, 0))
        ttk.Label(leftA, textvariable=self.status_view_A, foreground="gray").pack(anchor="w", pady=(6, 0))

        # ----- Viewer B -----
        rowB = ttk.Frame(frm)
        rowB.pack(expand=True, fill=tk.BOTH, padx=12, pady=(6, 12))
        rowB.columnconfigure(0, weight=1)

        leftB = ttk.Frame(rowB)
        leftB.grid(row=0, column=0, sticky="nsew")
        sideB = ttk.Frame(rowB)
        sideB.grid(row=0, column=1, sticky="ns", padx=(10, 0))

        ttk.Label(leftB, text="Category B").pack(anchor="w")
        self.viewer_B = ScrolledText(leftB, wrap="word", height=18, font=("TkDefaultFont", 11))
        self.viewer_B.pack(expand=True, fill=tk.BOTH, pady=(4, 0))
        self.viewer_B.config(state=tk.DISABLED)

        ttk.Button(sideB, text="Load B", command=lambda: self._on_load("B")).pack(fill=tk.X, pady=(4, 0))
        ttk.Label(leftB, textvariable=self.status_view_B, foreground="gray").pack(anchor="w", pady=(6, 0))

    # ---- Actions ----
    def _on_upload(self, category: str):
        pw = self.passphrase.get().strip()
        if not pw:
            target_status = self.status_submit_A if category == "A" else self.status_submit_B
            target_status.set("Enter your encryption password on the Password tab.")
            return

        entry = self.txt_A.get("1.0", tk.END).strip() if category == "A" else self.txt_B.get("1.0", tk.END).strip()
        target_status = self.status_submit_A if category == "A" else self.status_submit_B
        target_text = self.txt_A if category == "A" else self.txt_B

        try:
            saved_as = self.ctrl.submit_entry(pw, entry, category)
            target_status.set(f"Saved (encrypted) as {saved_as}")
            target_text.delete("1.0", tk.END)
        except Exception as e:
            target_status.set(f"Failed: {e}")

    def _on_load(self, category: str):
        pw = self.passphrase.get().strip()
        if not pw:
            messagebox.showinfo("Password needed", "Enter your encryption password on the Password tab.")
            return

        target_date = self.date_picker.get_date()
        target_view = self.viewer_A if category == "A" else self.viewer_B
        target_status = self.status_view_A if category == "A" else self.status_view_B

        target_view.config(state=tk.NORMAL)
        target_view.delete("1.0", tk.END)
        target_status.set("Loading…")
        self.update_idletasks()

        try:
            rows = self.ctrl.load_entries_for(pw, target_date, category)
            if not rows:
                target_status.set("No entries for that date.")
                target_view.config(state=tk.DISABLED)
                return

            for hhmm, text in rows:
                target_view.insert(tk.END, f"[{hhmm}] {text}\n\n")

            target_view.config(state=tk.DISABLED)
            target_status.set(f"Loaded {len(rows)} entr{'y' if len(rows)==1 else 'ies'} for {category}.")
        except RuntimeError as e:
            target_status.set(str(e))
            target_view.config(state=tk.DISABLED)
        except HttpError as e:
            target_status.set(f"HTTP error: {e}")
            target_view.config(state=tk.DISABLED)
        except Exception as e:
            target_status.set(f"Failed: {e}")
            target_view.config(state=tk.DISABLED)


# --------------------------
# Main
# --------------------------

def main():
    cfg = AppConfig()
    print("creds_path:", cfg.creds_path)
    print("token_path:", cfg.token_path)
    app = DailyApp(DailyController(cfg))
    app.mainloop()

if __name__ == "__main__":
    main()
