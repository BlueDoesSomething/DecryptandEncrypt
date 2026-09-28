import { Component } from '@angular/core';

type Cipher = 'caesar' | 'vigenere' | 'aes';

@Component({
  selector: 'app-home',
  templateUrl: 'home.page.html',
  styleUrls: ['home.page.scss'],
  standalone: false,
})
export class HomePage {
  cipher: Cipher = 'caesar';
  mode: 'encrypt' | 'decrypt' = 'encrypt';
  inputText = '';
  shift = 3;
  keyword = '';
  password = '';
  outputText = '';
  error = '';

  async run() {
    this.error = '';
    this.outputText = '';
    try {
      if (this.cipher === 'caesar') {
        this.outputText =
          this.mode === 'encrypt'
            ? this.caesarEncrypt(this.inputText, this.shift)
            : this.caesarDecrypt(this.inputText, this.shift);
      } else if (this.cipher === 'vigenere') {
        this.outputText =
          this.mode === 'encrypt'
            ? this.vigenereEncrypt(this.inputText, this.keyword)
            : this.vigenereDecrypt(this.inputText, this.keyword);
      } else {
        // AES-256-GCM, format salt:iv:data (base64) — same as Python
        this.outputText =
          this.mode === 'encrypt'
            ? await this.aesEncrypt(this.inputText, this.password)
            : await this.aesDecrypt(this.inputText, this.password);
      }
    } catch (e: any) {
      this.error = e?.message ?? String(e);
    }
  }

  copy() {
    if (this.outputText) navigator.clipboard.writeText(this.outputText);
  }

  clear() {
    this.inputText = '';
    this.outputText = '';
    this.error = '';
  }

  // ---------- Caesar (mirrors cipher_app.py) ----------
  caesarEncrypt(text: string, shift: number): string {
    shift = ((shift % 26) + 26) % 26;
    return [...text].map((ch) => {
      if (ch >= 'A' && ch <= 'Z')
        return String.fromCharCode(((ch.charCodeAt(0) - 65 + shift) % 26) + 65);
      if (ch >= 'a' && ch <= 'z')
        return String.fromCharCode(((ch.charCodeAt(0) - 97 + shift) % 26) + 97);
      return ch;
    }).join('');
  }
  caesarDecrypt(text: string, shift: number): string {
    return this.caesarEncrypt(text, -shift);
  }

  // ---------- Vigenere (mirrors cipher_app.py) ----------
  private cleanKey(kw: string): string {
    const k = kw.toUpperCase().replace(/[^A-Z]/g, '');
    if (!k) throw new Error('Keyword must contain at least one letter.');
    return k;
  }
  vigenereEncrypt(text: string, kw: string): string {
    const key = this.cleanKey(kw);
    let ki = 0;
    return [...text].map((ch) => {
      const s = key.charCodeAt(ki % key.length) - 65;
      if (ch >= 'A' && ch <= 'Z') { ki++; return String.fromCharCode(((ch.charCodeAt(0) - 65 + s) % 26) + 65); }
      if (ch >= 'a' && ch <= 'z') { ki++; return String.fromCharCode(((ch.charCodeAt(0) - 97 + s) % 26) + 97); }
      return ch;
    }).join('');
  }
  vigenereDecrypt(text: string, kw: string): string {
    const key = this.cleanKey(kw);
    let ki = 0;
    return [...text].map((ch) => {
      const s = key.charCodeAt(ki % key.length) - 65;
      if (ch >= 'A' && ch <= 'Z') { ki++; return String.fromCharCode(((ch.charCodeAt(0) - 65 - s + 26) % 26) + 65); }
      if (ch >= 'a' && ch <= 'z') { ki++; return String.fromCharCode(((ch.charCodeAt(0) - 97 - s + 26) % 26) + 97); }
      return ch;
    }).join('');
  }

  // ---------- AES-256-GCM via WebCrypto (compatible with Python) ----------
  private b64e(buf: ArrayBuffer | Uint8Array): string {
    const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = ''; b.forEach((c) => (s += String.fromCharCode(c)));
    return btoa(s);
  }
  private b64d(s: string): Uint8Array {
    const bin = atob(s.trim());
    const b = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
    return b;
  }
  private async deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt as BufferSource, iterations: 100000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }
  async aesEncrypt(plaintext: string, password: string): Promise<string> {
    if (!password) throw new Error('Password required for AES.');
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await this.deriveKey(password, salt);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, enc.encode(plaintext));
    return `${this.b64e(salt)}:${this.b64e(iv)}:${this.b64e(ct)}`;
  }
  async aesDecrypt(token: string, password: string): Promise<string> {
    if (!password) throw new Error('Password required for AES.');
    const parts = token.trim().split(':');
    if (parts.length !== 3) throw new Error('Invalid AES format. Expected salt:iv:data.');
    const [sSalt, sIv, sCt] = parts;
    const salt = this.b64d(sSalt), iv = this.b64d(sIv), ct = this.b64d(sCt);
    const key = await this.deriveKey(password, salt);
    try {
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, ct as BufferSource);
      return new TextDecoder().decode(pt);
    } catch {
      throw new Error('Decryption failed. Wrong password or corrupted data.');
    }
  }
}
