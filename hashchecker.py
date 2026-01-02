#!/usr/bin/env python3

import hashlib
import threading
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

CHUNK_SIZE = 1024 * 1024  # 1 MB


def hash_file(path, progress_callback=None):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        total = os.path.getsize(path)
        read = 0
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                read += len(chunk)
                if progress_callback and total > 0:
                    progress_callback(read, total)
    except Exception as e:
        return None, None, None, str(e)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest(), None


def hash_text(text):
    b = text.encode("utf-8")
    return hashlib.md5(b).hexdigest(), hashlib.sha1(b).hexdigest(), hashlib.sha256(b).hexdigest(), None


class HashApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Hash Checker and Viewer")
        self.geometry("760x480")
        self.resizable(True, True)
        self.create_widgets()

    def create_widgets(self):
        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        # File selection
        file_row = ttk.Frame(frm)
        file_row.pack(fill="x", pady=6)
        ttk.Label(file_row, text="File:").pack(side="left")
        self.file_var = tk.StringVar()
        self.file_entry = ttk.Entry(file_row, textvariable=self.file_var, width=70)
        self.file_entry.pack(side="left", padx=6, expand=True, fill="x")
        self.browse_btn = ttk.Button(file_row, text="Browse", command=self.browse_file)
        self.browse_btn.pack(side="left")

        # Text input
        ttk.Label(frm, text="Or paste text to hash:").pack(anchor="w", pady=(8, 0))
        self.text_box = tk.Text(frm, height=8, wrap="word")
        self.text_box.pack(fill="both", pady=4, expand=True)

        # Compute and status
        action_row = ttk.Frame(frm)
        action_row.pack(fill="x", pady=6)
        self.compute_btn = ttk.Button(action_row, text="Compute Hashes", command=self.compute_hashes)
        self.compute_btn.pack(side="left")
        self.clear_btn = ttk.Button(action_row, text="Clear", command=self.clear_all)
        self.clear_btn.pack(side="left", padx=6)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(action_row, textvariable=self.status_var).pack(side="right")

        # Progress bar
        self.progress = ttk.Progressbar(frm, mode="determinate")
        self.progress.pack(fill="x", pady=(4, 8))

        # Results
        results = ttk.Frame(frm)
        results.pack(fill="both", expand=True, pady=(6, 0))

        self.hash_vars = {
            "MD5": tk.StringVar(),
            "SHA1": tk.StringVar(),
            "SHA256": tk.StringVar()
        }
        self.copy_buttons = {}

        for name in ("MD5", "SHA1", "SHA256"):
            row = ttk.Frame(results)
            row.pack(fill="x", pady=4)
            ttk.Label(row, text=f"{name}:", width=8).pack(side="left")
            ent = ttk.Entry(row, textvariable=self.hash_vars[name], width=80)
            ent.pack(side="left", padx=6, expand=True, fill="x")
            btn = ttk.Button(row, text="Copy", command=lambda n=name: self.copy_hash(n))
            btn.pack(side="left", padx=4)
            self.copy_buttons[name] = btn

        # Verification
        ttk.Label(frm, text="Verify hash (paste here):").pack(anchor="w", pady=(8, 0))
        verify_row = ttk.Frame(frm)
        verify_row.pack(fill="x", pady=4)
        self.verify_var = tk.StringVar()
        self.verify_entry = ttk.Entry(verify_row, textvariable=self.verify_var, width=60)
        self.verify_entry.pack(side="left", padx=6, expand=True, fill="x")
        self.verify_btn = ttk.Button(verify_row, text="Check", command=self.verify_hash)
        self.verify_btn.pack(side="left")
        self.verify_result_var = tk.StringVar()
        ttk.Label(verify_row, textvariable=self.verify_result_var, foreground="blue").pack(side="left", padx=8)

        # Keep list of interactive widgets for enable/disable
        self._interactive_widgets = [
            self.file_entry, self.browse_btn, self.text_box,
            self.compute_btn, self.clear_btn, self.verify_entry, self.verify_btn
        ] + list(self.copy_buttons.values())

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_var.set(path)
            self.text_box.delete("1.0", "end")

    def compute_hashes(self):
        path = self.file_var.get().strip()
        text = self.text_box.get("1.0", "end").rstrip("\n")
        if not path and not text:
            messagebox.showinfo("Input required", "Select a file or paste text to hash.")
            return
        self.status_var.set("Computing...")
        self.progress["value"] = 0
        self.disable_ui()
        thread = threading.Thread(target=self._compute_worker, args=(path, text), daemon=True)
        thread.start()

    def _compute_worker(self, path, text):
        if path:
            def progress_cb(read, total):
                # schedule progress update on main thread
                self.after(0, self._update_progress, read, total)
            md5, sha1, sha256, err = hash_file(path, progress_callback=progress_cb)
        else:
            md5, sha1, sha256, err = hash_text(text)
            # set progress to complete for text
            self.after(0, lambda: self.progress.configure(value=100))
        self.after(0, self._compute_done, md5, sha1, sha256, err)

    def _update_progress(self, read, total):
        try:
            pct = (read / total) * 100
        except Exception:
            pct = 0
        self.progress.configure(value=pct)

    def _compute_done(self, md5, sha1, sha256, err):
        if err:
            messagebox.showerror("Error", f"Failed to compute hash: {err}")
            self.status_var.set("Error")
            self.progress.configure(value=0)
        else:
            self.hash_vars["MD5"].set(md5)
            self.hash_vars["SHA1"].set(sha1)
            self.hash_vars["SHA256"].set(sha256)
            self.status_var.set("Done")
            self.progress.configure(value=100)
        self.enable_ui()

    def verify_hash(self):
        candidate = self.verify_var.get().strip().lower()
        if not candidate:
            self.verify_result_var.set("Paste a hash to verify")
            return
        matches = []
        for name, var in self.hash_vars.items():
            val = var.get().strip().lower()
            if val and candidate == val:
                matches.append(name)
        if matches:
            self.verify_result_var.set("Matches: " + ", ".join(matches))
        else:
            self.verify_result_var.set("No match")

    def copy_hash(self, name):
        val = self.hash_vars[name].get()
        if val:
            try:
                self.clipboard_clear()
                self.clipboard_append(val)
                self.status_var.set(f"{name} copied to clipboard")
            except Exception:
                self.status_var.set("Clipboard error")
        else:
            self.status_var.set("Nothing to copy")

    def clear_all(self):
        self.file_var.set("")
        self.text_box.delete("1.0", "end")
        for v in self.hash_vars.values():
            v.set("")
        self.verify_var.set("")
        self.verify_result_var.set("")
        self.status_var.set("Ready")
        self.progress.configure(value=0)

    def disable_ui(self):
        for w in self._interactive_widgets:
            try:
                w_state = w.cget("state")
            except Exception:
                w_state = None
            # store previous state so enable_ui can restore if needed
            setattr(w, "_prev_state", w_state)
            try:
                w.configure(state="disabled")
            except Exception:
                # Text widget uses 'state' too, but some widgets may not support configure(state=)
                try:
                    w.config(state="disabled")
                except Exception:
                    pass

    def enable_ui(self):
        for w in self._interactive_widgets:
            prev = getattr(w, "_prev_state", None)
            try:
                if prev is None or prev == "normal":
                    w.configure(state="normal")
                else:
                    w.configure(state=prev)
            except Exception:
                try:
                    w.config(state="normal")
                except Exception:
                    pass


if __name__ == "__main__":
    app = HashApp()
    app.mainloop()
