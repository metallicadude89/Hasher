#!/usr/bin/env python3
"""
Simple Hash Checker and Viewer
Computes MD5, SHA1, SHA256 for files or text and verifies a provided hash.
"""

import hashlib
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

CHUNK_SIZE = 1024 * 1024  # 1 MB


def hash_file(path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
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
        self.geometry("700x420")
        self.resizable(False, False)
        self.create_widgets()

    def create_widgets(self):
        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        # File selection
        file_row = ttk.Frame(frm)
        file_row.pack(fill="x", pady=6)
        ttk.Label(file_row, text="File:").pack(side="left")
        self.file_var = tk.StringVar()
        self.file_entry = ttk.Entry(file_row, textvariable=self.file_var, width=60)
        self.file_entry.pack(side="left", padx=6)
        ttk.Button(file_row, text="Browse", command=self.browse_file).pack(side="left")

        # Text input
        ttk.Label(frm, text="Or paste text to hash:").pack(anchor="w", pady=(8, 0))
        self.text_box = tk.Text(frm, height=6, wrap="word")
        self.text_box.pack(fill="x", pady=4)

        # Compute and status
        action_row = ttk.Frame(frm)
        action_row.pack(fill="x", pady=6)
        ttk.Button(action_row, text="Compute Hashes", command=self.compute_hashes).pack(side="left")
        ttk.Button(action_row, text="Clear", command=self.clear_all).pack(side="left", padx=6)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(action_row, textvariable=self.status_var).pack(side="right")

        # Results
        results = ttk.Frame(frm)
        results.pack(fill="both", expand=True, pady=(6, 0))

        self.hash_vars = {
            "MD5": tk.StringVar(),
            "SHA1": tk.StringVar(),
            "SHA256": tk.StringVar()
        }

        for name in ("MD5", "SHA1", "SHA256"):
            row = ttk.Frame(results)
            row.pack(fill="x", pady=4)
            ttk.Label(row, text=f"{name}:", width=8).pack(side="left")
            ent = ttk.Entry(row, textvariable=self.hash_vars[name], width=70)
            ent.pack(side="left", padx=6)
            ttk.Button(row, text="Copy", command=lambda n=name: self.copy_hash(n)).pack(side="left", padx=4)

        # Verification
        ttk.Label(frm, text="Verify hash (paste here):").pack(anchor="w", pady=(8, 0))
        verify_row = ttk.Frame(frm)
        verify_row.pack(fill="x", pady=4)
        self.verify_var = tk.StringVar()
        ttk.Entry(verify_row, textvariable=self.verify_var, width=60).pack(side="left", padx=6)
        ttk.Button(verify_row, text="Check", command=self.verify_hash).pack(side="left")
        self.verify_result_var = tk.StringVar()
        ttk.Label(verify_row, textvariable=self.verify_result_var, foreground="blue").pack(side="left", padx=8)

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_var.set(path)
            self.text_box.delete("1.0", "end")

    def compute_hashes(self):
        path = self.file_var.get().strip()
        text = self.text_box.get("1.0", "end").strip()
        if not path and not text:
            messagebox.showinfo("Input required", "Select a file or paste text to hash.")
            return
        self.status_var.set("Computing...")
        self.disable_ui()
        thread = threading.Thread(target=self._compute_worker, args=(path, text), daemon=True)
        thread.start()

    def _compute_worker(self, path, text):
        if path:
            md5, sha1, sha256, err = hash_file(path)
        else:
            md5, sha1, sha256, err = hash_text(text)
        self.after(0, self._compute_done, md5, sha1, sha256, err)

    def _compute_done(self, md5, sha1, sha256, err):
        if err:
            messagebox.showerror("Error", f"Failed to compute hash: {err}")
            self.status_var.set("Error")
        else:
            self.hash_vars["MD5"].set(md5)
            self.hash_vars["SHA1"].set(sha1)
            self.hash_vars["SHA256"].set(sha256)
            self.status_var.set("Done")
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
            self.clipboard_clear()
            self.clipboard_append(val)
            self.status_var.set(f"{name} copied to clipboard")
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

    def disable_ui(self):
        for child in self.winfo_children():
            child_state = getattr(child, "state", None)
        # minimal disable: prevent repeated compute
        for btn in self.winfo_children():
            pass

    def enable_ui(self):
        pass


if __name__ == "__main__":
    app = HashApp()
    app.mainloop()
