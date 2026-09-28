"""Cipher App GUI - Tkinter UI (mirrors cipher_app.py + Ionic page). Run: python cipher_gui.py"""
import tkinter as tk
from tkinter import ttk, messagebox

from cipher_app import (
    caesar_encrypt, caesar_decrypt,
    vigenere_encrypt, vigenere_decrypt,
    aes_encrypt, aes_decrypt,
)

class CipherGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Encrypt / Decrypt App")
        self.geometry("620x640")
        self.resizable(True, True)

        # --- Top controls ---
        top = ttk.Frame(self, padding=12)
        top.pack(fill="x")

        ttk.Label(top, text="Cipher:").grid(row=0, column=0, sticky="w")
        self.cipher = tk.StringVar(value="Caesar")
        self.cipher_box = ttk.Combobox(top, textvariable=self.cipher, state="readonly",
                                       values=["Caesar", "Vigenere", "AES-256-GCM"], width=18)
        self.cipher_box.grid(row=0, column=1, sticky="w", padx=6)
        self.cipher_box.bind("<<ComboboxSelected>>", lambda e: self.refresh_fields())

        ttk.Label(top, text="Mode:").grid(row=0, column=2, padx=(16, 0))
        self.mode = tk.StringVar(value="Encrypt")
        ttk.Radiobutton(top, text="Encrypt", variable=self.mode, value="Encrypt").grid(row=0, column=3, padx=4)
        ttk.Radiobutton(top, text="Decrypt", variable=self.mode, value="Decrypt").grid(row=0, column=4, padx=4)

        # --- Key frame (changes per cipher) ---
        self.key_frame = ttk.LabelFrame(self, text="Key", padding=10)
        self.key_frame.pack(fill="x", padx=12, pady=(0, 8))

        ttk.Label(self.key_frame, text="Shift (0-25):").grid(row=0, column=0, sticky="w")
        self.shift = tk.IntVar(value=3)
        self.shift_spin = ttk.Spinbox(self.key_frame, from_=0, to=25, textvariable=self.shift, width=8)
        self.shift_spin.grid(row=0, column=1, sticky="w", padx=6)

        ttk.Label(self.key_frame, text="Keyword:").grid(row=1, column=0, sticky="w", pady=4)
        self.keyword = tk.StringVar()
        self.keyword_entry = ttk.Entry(self.key_frame, textvariable=self.keyword, width=30)
        self.keyword_entry.grid(row=1, column=1, columnspan=2, sticky="ew", padx=6)

        ttk.Label(self.key_frame, text="Password:").grid(row=2, column=0, sticky="w")
        self.password = tk.StringVar()
        self.pw_entry = ttk.Entry(self.key_frame, textvariable=self.password, show="*", width=30)
        self.pw_entry.grid(row=2, column=1, sticky="ew", padx=6)
        self.show_pw = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.key_frame, text="Show", variable=self.show_pw,
                        command=lambda: self.pw_entry.config(show="" if self.show_pw.get() else "*")
                        ).grid(row=2, column=2, padx=4)

        # --- Input / Output ---
        ttk.Label(self, text="Input (plaintext / ciphertext):").pack(anchor="w", padx=14)
        self.input_txt = tk.Text(self, height=6, wrap="word")
        self.input_txt.pack(fill="both", padx=12, pady=(2, 8), expand=False)

        btns = ttk.Frame(self, padding=(12, 0))
        btns.pack(fill="x")
        ttk.Button(btns, text="Run", command=self.run).pack(side="left", expand=True, fill="x", padx=(0, 4))
        ttk.Button(btns, text="Copy Result", command=self.copy).pack(side="left", expand=True, fill="x", padx=4)
        ttk.Button(btns, text="Clear", command=self.clear).pack(side="left", expand=True, fill="x", padx=(4, 0))

        ttk.Label(self, text="Result:").pack(anchor="w", padx=14, pady=(8, 0))
        self.output_txt = tk.Text(self, height=6, wrap="word", state="disabled", bg="#f4f4f4")
        self.output_txt.pack(fill="both", padx=12, pady=(2, 12), expand=True)

        self.refresh_fields()

    def refresh_fields(self):
        c = self.cipher.get()
        # enable only relevant row
        self.shift_spin.config(state="normal" if c == "Caesar" else "disabled")
        self.keyword_entry.config(state="normal" if c == "Vigenere" else "disabled")
        self.pw_entry.config(state="normal" if c.startswith("AES") else "disabled")

    def run(self):
        text = self.input_txt.get("1.0", "end-1c")
        if not text.strip():
            messagebox.showwarning("Empty", "Enter plaintext / ciphertext first.")
            return
        is_enc = self.mode.get() == "Encrypt"
        try:
            c = self.cipher.get()
            if c == "Caesar":
                res = caesar_encrypt(text, self.shift.get()) if is_enc else caesar_decrypt(text, self.shift.get())
            elif c == "Vigenere":
                if not self.keyword.get().strip():
                    raise ValueError("Keyword required.")
                res = vigenere_encrypt(text, self.keyword.get()) if is_enc else vigenere_decrypt(text, self.keyword.get())
            else:
                if not self.password.get():
                    raise ValueError("Password required for AES.")
                res = aes_encrypt(text, self.password.get()) if is_enc else aes_decrypt(text, self.password.get())
            self.output_txt.config(state="normal")
            self.output_txt.delete("1.0", "end")
            self.output_txt.insert("1.0", res)
            self.output_txt.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def copy(self):
        res = self.output_txt.get("1.0", "end-1c")
        if res:
            self.clipboard_clear(); self.clipboard_append(res)

    def clear(self):
        self.input_txt.delete("1.0", "end")
        self.output_txt.config(state="normal")
        self.output_txt.delete("1.0", "end")
        self.output_txt.config(state="disabled")

if __name__ == "__main__":
    CipherGUI().mainloop()
