// src/crypto.ts
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

// Web Crypto доступен только в защищённом контексте (HTTPS / localhost)
const hasSubtle = typeof crypto !== 'undefined' && crypto.subtle !== undefined;

/**
 * SHA-256 в hex-формате.
 * В защищённом контексте — нативный быстрый API.
 * По HTTP — фоллбэк на @noble/hashes (результат идентичен).
 */
export async function sha256(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  if (hasSubtle) {
    const source = new Uint8Array(bytes).buffer;
    const digest = await crypto.subtle.digest('SHA-256', source);
    return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
  }
  return bytesToHex(nobleSha256(bytes));
}


// SHA-256 в Uint8Array.
export async function sha256Bytes(data: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  if (hasSubtle) {
    const source = new Uint8Array(bytes).buffer;
    return new Uint8Array(await crypto.subtle.digest('SHA-256', source));
  }
  return nobleSha256(bytes);
}

/**
 * UUID v4.
 * В защищённом контексте — crypto.randomUUID().
 * По HTTP — простой фоллбэк (подходит только для локальных идентификаторов).
 */
export function randomUUID(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
