// Minimal TOTP (RFC 6238) — no external dependency besides Node's crypto.
const crypto = require("crypto");
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buf) {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  let bits = 0, value = 0; const out = [];
  for (const ch of str.replace(/=+$/, "").toUpperCase()) {
    const idx = B32.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

function generateSecret() { return base32Encode(crypto.randomBytes(20)); }

function hotp(secret, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac("sha1", base32Decode(secret)).update(buf).digest();
  const off = h[h.length - 1] & 15;
  const code = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(code % 1000000).padStart(6, "0");
}

function verifyTotp(secret, token, window = 1) {
  token = String(token || "").replace(/\s+/g, "");
  if (!/^\d{6}$/.test(token) || !secret) return false;
  const step = Math.floor(Date.now() / 30000);
  let ok = false;
  for (let w = -window; w <= window; w++) {
    const expected = Buffer.from(hotp(secret, step + w));
    if (crypto.timingSafeEqual(expected, Buffer.from(token))) ok = true;
  }
  return ok;
}

function otpauthUrl(secret, account, issuer) {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

// Only allow same-site relative redirects (prevents open-redirect after login).
function safeNext(n, fallback = "/") {
  if (typeof n !== "string" || !n.startsWith("/") || n.startsWith("//") || n.startsWith("/\\")) return fallback;
  return n;
}

// Discord snowflake -> account creation time (ms).
function discordCreatedAt(id) {
  try { return Number((BigInt(id) >> 22n) + 1420070400000n); } catch (e) { return 0; }
}

// ---- delivery codes: AES-256-GCM encryption at rest -------------------------
// Key source: CODES_KEY env var (recommended) or an auto-generated key file
// kept next to the database (never inside backups/). Losing the key = losing
// the ability to read stored codes, so keep a copy somewhere safe.
const fs = require("fs");
const path = require("path");
let _codesKey = null, _codesKeySource = "";
function codesKey(dir) {
  if (_codesKey) return _codesKey;
  if (process.env.CODES_KEY) {
    _codesKey = crypto.createHash("sha256").update(String(process.env.CODES_KEY)).digest();
    _codesKeySource = "env";
    return _codesKey;
  }
  const file = path.join(dir, "codes.key");
  if (fs.existsSync(file)) {
    _codesKey = Buffer.from(fs.readFileSync(file, "utf8").trim(), "hex");
  } else {
    _codesKey = crypto.randomBytes(32);
    fs.writeFileSync(file, _codesKey.toString("hex"), { mode: 0o600 });
  }
  _codesKeySource = "file";
  return _codesKey;
}
function codesKeySource() { return _codesKeySource; }

function encryptCode(plain, dir) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", codesKey(dir), iv);
  const enc = Buffer.concat([c.update(String(plain), "utf8"), c.final()]);
  return "enc1:" + Buffer.concat([iv, c.getAuthTag(), enc]).toString("base64");
}
function decryptCode(stored, dir) {
  if (typeof stored !== "string" || !stored.startsWith("enc1:")) return stored; // legacy plaintext
  try {
    const raw = Buffer.from(stored.slice(5), "base64");
    const d = crypto.createDecipheriv("aes-256-gcm", codesKey(dir), raw.subarray(0, 12));
    d.setAuthTag(raw.subarray(12, 28));
    return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString("utf8");
  } catch (e) {
    return "⚠ تعذّر فك التشفير (مفتاح مختلف)";
  }
}
function hashCode(plain, dir) {
  return crypto.createHmac("sha256", codesKey(dir)).update(String(plain).trim().toLowerCase()).digest("hex");
}
function maskCode(plain) {
  const p = String(plain);
  return p.length <= 6 ? "••••••" : p.slice(0, 3) + "•".repeat(Math.min(10, p.length - 5)) + p.slice(-2);
}

module.exports = {
  codesKey, codesKeySource, encryptCode, decryptCode, hashCode, maskCode, generateSecret, verifyTotp, otpauthUrl, safeNext, discordCreatedAt, hotp };
