/**
 * The C2SP transparency-log formats the public witness network speaks.
 * docs/transparency-log.md.
 *
 *   c2sp.org/signed-note       a text, a blank line, one "— name base64(keyID || sig)" line per signature
 *   c2sp.org/tlog-checkpoint   origin / tree size / base64 root, as the signed text
 *   c2sp.org/tlog-cosignature  a witness's timestamped Ed25519 signature (type 0x04)
 *   c2sp.org/tlog-tiles        the tree as 256-hash tiles at tile/<L>/<N>[.p/<W>]
 *
 * Our log signs with Ed25519 (type 0x01). The checkpoint text is frozen
 * (rules 9 and 15): for our origin it is exactly three lines, and its root is
 * the v2 head's root_hash in base64 instead of hex.
 *
 * WebCrypto only, so the Worker, Node and the public verifier repository
 * share this file. Hashes cross the boundary with tools/merkle.mjs as
 * lowercase hex, as everywhere else in this repository.
 */
import { rootHash } from './merkle.mjs';

export const ORIGIN = 'api.riskrouter.eu/tlog/evidence-v2';
export const TYPE_ED25519 = 0x01;
export const TYPE_COSIGNATURE_V1 = 0x04;
const EM_DASH = '—';
const MAX_SIGNATURES = 64;

const te = new TextEncoder();
const bytesToB64 = (bytes) => { let s = ''; for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b); return btoa(s); };
const b64ToBytes = (b64) => {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64) || b64.length % 4) throw new Error('not standard base64');
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
};
const hexOf = (bytes) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
const unhex = (h) => Uint8Array.from(h.match(/../g) || [], (b) => parseInt(b, 16));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

export const hexToB64 = (h) => bytesToB64(unhex(h));
export const b64ToHex = (b) => hexOf(b64ToBytes(b));

/** A key name: non-empty, no Unicode spaces, no plus. */
function checkName(name) {
  if (typeof name !== 'string' || !name || /[\s+]/u.test(name)) throw new Error(`not a valid key name: ${JSON.stringify(name)}`);
  return name;
}

/** key ID = SHA-256(name || 0x0A || type || public key)[:4], as 8 lowercase hex characters. */
export async function keyId(name, type, publicKey) {
  return hexOf((await sha256(concat(te.encode(checkName(name)), Uint8Array.of(0x0a, type), publicKey))).slice(0, 4));
}

/** A verifier key: name+hex(key ID)+base64(type || public key). */
export async function encodeVkey(name, type, publicKey) {
  return `${checkName(name)}+${await keyId(name, type, publicKey)}+${bytesToB64(concat(Uint8Array.of(type), publicKey))}`;
}

/** A vkey, checked: a known type, a 32-byte Ed25519 key, and the key ID it must have. */
export async function parseVkey(vkey) {
  // The key material is base64, which may itself contain "+": split at the first two only.
  const m = String(vkey).trim().match(/^([^+]+)\+([^+]+)\+(.+)$/s);
  if (!m) throw new Error('a vkey is name+keyid+key');
  const [, name, id, material] = m;
  checkName(name);
  if (!/^[0-9a-f]{8}$/.test(id)) throw new Error('a vkey key ID is 8 lowercase hex characters');
  const raw = b64ToBytes(material);
  const type = raw[0];
  const publicKey = raw.slice(1);
  if (type !== TYPE_ED25519 && type !== TYPE_COSIGNATURE_V1) throw new Error(`signature type 0x${type?.toString(16)} is not supported here`);
  if (publicKey.length !== 32) throw new Error('an Ed25519 public key is 32 bytes');
  if (await keyId(name, type, publicKey) !== id) throw new Error('the vkey\'s key ID does not match its name and key');
  return { name, id, type, publicKey, vkey: `${name}+${id}+${material}` };
}

/**
 * A signed note, split: the text (with its final newline) and its signature
 * lines. Refuses what c2sp.org/signed-note refuses: control characters other
 * than newline, a text that does not end in a newline, malformed lines.
 */
export function parseNote(note) {
  if (typeof note !== 'string') throw new Error('a note is text');
  if (/[\u0000-\u0009\u000b-\u001f]/.test(note)) throw new Error('a note may contain no control characters other than newline');
  const split = note.lastIndexOf('\n\n');
  if (split < 0) throw new Error('a note has a text, a blank line, then signatures');
  const text = note.slice(0, split + 1);
  const lines = note.slice(split + 2).split('\n');
  if (lines.pop() !== '') throw new Error('a note ends with a newline');
  if (!lines.length) throw new Error('a note has at least one signature');
  if (lines.length > MAX_SIGNATURES) throw new Error('too many signatures');
  const signatures = lines.map((line) => {
    const m = line.match(/^— (\S+) ([A-Za-z0-9+/]+={0,2})$/u);
    if (!m) throw new Error(`not a signature line: ${line.slice(0, 80)}`);
    const raw = b64ToBytes(m[2]);
    if (raw.length < 5) throw new Error('a signature is a key ID and at least one byte');
    return { name: m[1], id: hexOf(raw.slice(0, 4)), signature: raw.slice(4), line: `${line}\n` };
  });
  return { text, signatures };
}

export const signatureLine = (name, id, signature) => `${EM_DASH} ${checkName(name)} ${bytesToB64(concat(unhex(id), signature))}\n`;

/** The Ed25519 signed message of a cosignature/v1 over a checkpoint text. */
export function cosignatureMessage(text, timestamp) {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) throw new Error('a cosignature timestamp is a whole number of seconds');
  return `cosignature/v1\ntime ${timestamp}\n${text}`;
}

const importVerify = (publicKey) => crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);

async function verifyOne(key, sig, text) {
  const pub = await importVerify(key.publicKey);
  if (key.type === TYPE_ED25519) {
    if (sig.signature.length !== 64) return { ok: false };
    return { ok: await crypto.subtle.verify({ name: 'Ed25519' }, pub, sig.signature, te.encode(text)) };
  }
  // cosignature/v1: u64 big-endian timestamp, then the Ed25519 signature.
  if (sig.signature.length !== 72) return { ok: false };
  const view = new DataView(sig.signature.buffer, sig.signature.byteOffset, 8);
  const timestamp = Number(view.getBigUint64(0));
  if (!Number.isSafeInteger(timestamp)) return { ok: false };
  const ok = await crypto.subtle.verify({ name: 'Ed25519' }, pub, sig.signature.slice(8), te.encode(cosignatureMessage(text, timestamp)));
  return { ok, timestamp };
}

/**
 * Verify a note against the keys you trust, as c2sp.org/signed-note says:
 * signatures from unknown keys are ignored; a known key whose signature fails
 * rejects the note; at least one known key must verify. Returns the text and
 * who signed it (with each cosignature's time).
 */
export async function verifyNote(note, vkeys) {
  let parsed;
  try { parsed = parseNote(note); } catch (e) { return { ok: false, reason: e.message }; }
  const keys = [];
  for (const v of vkeys) keys.push(typeof v === 'string' ? await parseVkey(v) : v);
  const verified = [];
  for (const sig of parsed.signatures) {
    const key = keys.find((k) => k.name === sig.name && k.id === sig.id);
    if (!key) continue;
    const r = await verifyOne(key, sig, parsed.text);
    if (!r.ok) return { ok: false, reason: `the signature by ${sig.name} (${sig.id}) does not verify` };
    verified.push({ name: key.name, id: key.id, type: key.type, ...(r.timestamp != null ? { timestamp: r.timestamp } : {}), line: sig.line });
  }
  if (!verified.length) return { ok: false, reason: 'no signature from a key you trust' };
  return { ok: true, text: parsed.text, verified };
}

/* ------------------------------------------------------------ checkpoints */

/** The frozen checkpoint text: origin, size, base64 root, each ending in a newline, nothing more. */
export function checkpointText({ origin = ORIGIN, tree_size, root_hash }) {
  if (!Number.isSafeInteger(tree_size) || tree_size < 0) throw new Error('tree_size is a whole number');
  if (!/^[0-9a-f]{64}$/.test(root_hash)) throw new Error('root_hash is 64 lowercase hex characters');
  return `${checkName(origin)}\n${tree_size}\n${hexToB64(root_hash)}\n`;
}

/** A checkpoint text, read. `strict` refuses extension lines, which our origin never has. */
export function parseCheckpoint(text, { strict = true } = {}) {
  const lines = text.split('\n');
  if (lines.pop() !== '') throw new Error('a checkpoint text ends with a newline');
  if (lines.length < 3 || lines.some((l) => l === '')) throw new Error('a checkpoint has an origin, a size and a root, each non-empty');
  if (strict && lines.length !== 3) throw new Error('this checkpoint has extension lines, which ours never has');
  const [origin, size, root] = lines;
  if (!/^(0|[1-9]\d{0,15})$/.test(size) || !Number.isSafeInteger(Number(size))) throw new Error('the size is a decimal with no leading zeroes');
  const rootBytes = b64ToBytes(root);
  if (rootBytes.length !== 32) throw new Error('the root is 32 bytes');
  return { origin, tree_size: Number(size), root_hash: hexOf(rootBytes), extensions: lines.slice(3) };
}

/** An Ed25519 signer from a PKCS#8 private key in base64, with its public key and vkey. */
export async function ed25519Signer(pkcs8B64, name, type = TYPE_ED25519) {
  const der = b64ToBytes(String(pkcs8B64).trim());
  const exportable = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', exportable);
  const publicKey = b64ToBytes(jwk.x.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - jwk.x.length % 4) % 4));
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']);
  const id = await keyId(name, type, publicKey);
  return {
    name, type, id, publicKey,
    vkey: await encodeVkey(name, type, publicKey),
    sign: async (bytes) => new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, key, bytes))
  };
}

/** Our signature line on a checkpoint text. */
export async function signCheckpoint(text, signer) {
  if (signer.type !== TYPE_ED25519) throw new Error('a log signs with an Ed25519 note key');
  return signatureLine(signer.name, signer.id, await signer.sign(te.encode(text)));
}

/** A witness's cosignature/v1 line (for witnesses, and for tests). */
export async function cosignCheckpoint(text, signer, timestamp) {
  if (signer.type !== TYPE_COSIGNATURE_V1) throw new Error('a cosignature/v1 key has type 0x04');
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(0, BigInt(timestamp));
  return signatureLine(signer.name, signer.id, concat(ts, await signer.sign(te.encode(cosignatureMessage(text, timestamp)))));
}

/** A new Ed25519 key: the private half as base64 PKCS#8, and the signer. */
export async function newEd25519Key(name, type = TYPE_ED25519) {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pkcs8 = bytesToB64(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  return { private_pkcs8_b64: pkcs8, signer: await ed25519Signer(pkcs8, name, type) };
}

/* ------------------------------------------------------------------ tiles */

/** tile/<L>/<N>[.p/<W>], N in x-prefixed three-digit groups (c2sp.org/tlog-tiles). */
export function tilePath(level, index, width = 256) {
  const groups = [];
  let n = index;
  do { groups.unshift(String(n % 1000).padStart(3, '0')); n = Math.floor(n / 1000); } while (n > 0);
  const encoded = groups.map((g, i) => (i < groups.length - 1 ? `x${g}` : g)).join('/');
  return `tile/${level}/${encoded}${width < 256 ? `.p/${width}` : ''}`;
}

/** The inverse of tilePath, or null. `entries` marks an entry bundle, which we never serve. */
export function parseTilePath(p) {
  const m = String(p).match(/^tile\/(entries|0|[1-9]\d?)\/((?:x\d{3}\/)*\d{3})(?:\.p\/([1-9]\d{0,2}))?$/);
  if (!m) return null;
  const width = m[3] ? Number(m[3]) : 256;
  if (width > 255 && m[3]) return null;
  const index = m[2].split('/').reduce((n, g) => n * 1000 + Number(g.replace('x', '')), 0);
  if (!Number.isSafeInteger(index)) return null;
  const level = m[1] === 'entries' ? null : Number(m[1]);
  if (level !== null && level > 63) return null;
  return { entries: m[1] === 'entries', level, index, width, partial: Boolean(m[3]) };
}

/** How many hashes tile level L has for a tree of `size` leaves. */
export const hashesAtLevel = (size, level) => Math.floor(size / 256 ** level);

/** Every tile a tree of `size` needs, as { level, index, width }, level 0 first. */
export function tilesFor(size) {
  const tiles = [];
  for (let level = 0; hashesAtLevel(size, level) > 0; level++) {
    const count = hashesAtLevel(size, level);
    for (let index = 0; index * 256 < count; index++) tiles.push({ level, index, width: Math.min(256, count - index * 256) });
  }
  return tiles;
}

const splitTile = (bytes) => {
  if (bytes.length % 32) throw new Error('a tile is a whole number of 32-byte hashes');
  const out = [];
  for (let i = 0; i < bytes.length; i += 32) out.push(hexOf(bytes.slice(i, i + 32)));
  return out;
};

/**
 * Fetch every tile a tree of `size` needs and check them: each tile has the
 * width it should, every hash above level 0 is the root of the full tile below
 * it, and the leaf hashes give `root_hash`. `getTile(path)` returns bytes.
 * This is a hash mirror: all a monitor needs to check roots and proofs.
 */
export async function checkTiles({ tree_size, root_hash, getTile }) {
  const byLevel = [];
  for (const t of tilesFor(tree_size)) {
    const bytes = await getTile(tilePath(t.level, t.index, t.width));
    const hashes = splitTile(new Uint8Array(bytes));
    if (hashes.length !== t.width) throw new Error(`${tilePath(t.level, t.index, t.width)} holds ${hashes.length} hashes, not ${t.width}`);
    (byLevel[t.level] ||= []).push(...hashes);
  }
  for (let level = 1; level < byLevel.length; level++) {
    for (let i = 0; i < byLevel[level].length; i++) {
      const below = byLevel[level - 1].slice(i * 256, (i + 1) * 256);
      if (await rootHash(below) !== byLevel[level][i]) throw new Error(`tile level ${level} hash ${i} is not the root of the tile below it`);
    }
  }
  const got = await rootHash(byLevel[0] || []);
  if (got !== root_hash) throw new Error(`the tiles give root ${got}, not the checkpoint's ${root_hash}`);
  return { tree_size, root_hash, tiles: tilesFor(tree_size).length, leaves: (byLevel[0] || []).length };
}
