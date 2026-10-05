/**
 * SCITT on the v2 evidence log: Signed Statements in, COSE Receipts out.
 * docs/scitt.md.
 *
 *   IETF SCITT architecture (draft-ietf-scitt-architecture): Signed Statement,
 *     Receipt, Transparent Statement (receipts in unprotected header 394).
 *   RFC 9942 (COSE Receipts): vds 395 = 1 (RFC9162_SHA256), vdp 396 with
 *     inclusion proofs at -1: bstr .cbor [tree_size, leaf_index, [path...]],
 *     detached payload = the Merkle root.
 *   draft-ietf-cose-hash-envelope: payload = hash of the artifact, protected
 *     258 (payload hash alg) = -16 (SHA-256).
 *
 * Our registration policy, frozen as riskrouter-scitt-profile|1:
 *   - COSE_Sign1 (tag 18), ES256 (alg -7) in the protected header;
 *   - kid (4): the 16-hex id of a key the caller registered with
 *     POST /api/v2/evidence/keys, as UTF-8 bytes;
 *   - CWT claims (15) with iss (1) and sub (2), text, iss at most 8192
 *     characters, sub at most 1024, neither an email address;
 *   - a hash envelope: 258 = -16 and a 32-byte payload, so the record never
 *     reaches the log (rule 15), only its hash does;
 *   - the signature verifies with that key.
 * What the log keeps is one v2 leaf of kind `scitt.statement` whose
 * record_digest is SHA-256 of the statement re-encoded with an empty
 * unprotected header (as the architecture requires before registration):
 *
 *   statement_digest = SHA-256( 0xD2 0x84 || bstr(protected) || 0xA0 || bstr(payload) || bstr(signature) )
 *
 * A receipt is an RFC 9942 COSE_Sign1 signed with the log's head-signing key
 * (ES256, kid = the key id as UTF-8), whose protected header also carries
 * CWT claims (iss = the log, sub = the statement digest, iat) and the fields
 * that rebuild our frozen leaf string ("riskrouter-leaf").
 *
 * WebCrypto only: the Worker, Node and the verifier repository share it.
 */
import { leafHash, leafString, nodeHash } from './merkle.mjs';

export const PROFILE = 'riskrouter-scitt-profile|1';
export const RECEIPT_PROFILE = 'riskrouter-scitt-receipt|1';
export const STATEMENT_KIND = 'scitt.statement';
export const LABEL = { alg: 1, contentType: 3, kid: 4, typ: 16, cwt: 15, receipts: 394, vds: 395, vdp: 396, payloadHashAlg: 258 };
export const ES256 = -7;
export const SHA256_ALG = -16;
export const RFC9162_SHA256 = 1;
export const INCLUSION = -1;
export const MAX_STATEMENT_BYTES = 16384;

export class CoseError extends Error {}

const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const sha256 = async (b) => new Uint8Array(await crypto.subtle.digest('SHA-256', b));

/* ------------------------------------------------------------------ CBOR */

/** A CBOR tag, as decoded and as given to encode(). */
export class Tag {
  constructor(tag, value) { this.tag = tag; this.value = value; }
}

function head(major, n) {
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 0x100) return Uint8Array.of((major << 5) | 24, n);
  if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff);
  if (n < 0x100000000) return Uint8Array.of((major << 5) | 26, n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
  const out = new Uint8Array(9);
  out[0] = (major << 5) | 27;
  new DataView(out.buffer).setBigUint64(1, BigInt(n));
  return out;
}

/**
 * Deterministic CBOR (RFC 8949 §4.2.1): shortest heads, definite lengths, map
 * keys in bytewise order of their encoding. Integers, byte strings (Uint8Array),
 * text, arrays, Maps (or plain objects with text keys), tags, null, booleans.
 */
export function encode(v) {
  if (v === null) return Uint8Array.of(0xf6);
  if (v === true) return Uint8Array.of(0xf5);
  if (v === false) return Uint8Array.of(0xf4);
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new CoseError('only whole numbers are encoded');
    return v >= 0 ? head(0, v) : head(1, -1 - v);
  }
  if (v instanceof Uint8Array) return concat(head(2, v.length), v);
  if (typeof v === 'string') { const b = te.encode(v); return concat(head(3, b.length), b); }
  if (Array.isArray(v)) return concat(head(4, v.length), ...v.map(encode));
  if (v instanceof Tag) return concat(head(6, v.tag), encode(v.value));
  const entries = v instanceof Map ? [...v.entries()] : Object.entries(v);
  const encoded = entries.map(([k, val]) => [encode(k), encode(val)]);
  encoded.sort((a, b) => {
    for (let i = 0; i < Math.min(a[0].length, b[0].length); i++) if (a[0][i] !== b[0][i]) return a[0][i] - b[0][i];
    return a[0].length - b[0].length;
  });
  return concat(head(5, encoded.length), ...encoded.flat());
}

/**
 * Strict decoding: definite lengths only, no floats, no undefined or simple
 * values beyond false/true/null, no duplicate map keys, at most 16 deep, and
 * nothing after the item. Maps decode to Map; byte strings to Uint8Array.
 */
export function decode(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let o = 0;
  const need = (n) => { if (o + n > b.length) throw new CoseError('CBOR ends early'); };
  function arg(info) {
    if (info < 24) return info;
    const n = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
    if (!n) throw new CoseError('indefinite lengths and reserved values are not accepted');
    need(n);
    let v = 0n;
    for (let i = 0; i < n; i++) v = (v << 8n) | BigInt(b[o + i]);
    o += n;
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new CoseError('a number beyond 2^53 is not accepted');
    const num = Number(v);
    if (num < { 1: 24, 2: 0x100, 4: 0x10000, 8: 0x100000000 }[n]) throw new CoseError('CBOR that is not in its shortest form is not accepted');
    return num;
  }
  function item(depth) {
    if (depth > 16) throw new CoseError('CBOR nested too deep');
    need(1);
    const ib = b[o++];
    const major = ib >> 5;
    const info = ib & 0x1f;
    if (major === 7) {
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      throw new CoseError('floats and simple values are not accepted');
    }
    const n = arg(info);
    switch (major) {
      case 0: return n;
      case 1: return -1 - n;
      case 2: { need(n); const v = b.slice(o, o + n); o += n; return v; }
      case 3: { need(n); const v = td.decode(b.subarray(o, o + n)); o += n; return v; }
      case 4: { const a = []; for (let i = 0; i < n; i++) a.push(item(depth + 1)); return a; }
      case 5: {
        const m = new Map();
        const seen = new Set();
        for (let i = 0; i < n; i++) {
          const start = o;
          const k = item(depth + 1);
          const kb = hex(b.subarray(start, o));
          if (seen.has(kb)) throw new CoseError('a map key appears twice');
          seen.add(kb);
          m.set(k, item(depth + 1));
        }
        return m;
      }
      case 6: return new Tag(n, item(depth + 1));
      default: throw new CoseError('unknown CBOR major type');
    }
  }
  const v = item(0);
  if (o !== b.length) throw new CoseError('bytes after the CBOR item');
  return v;
}

/* ------------------------------------------------------------- COSE_Sign1 */

/** A COSE_Sign1 (tag 18), split: the protected bytes and map, unprotected map, payload, signature. */
export function parseSign1(bytes) {
  const t = decode(bytes);
  if (!(t instanceof Tag) || t.tag !== 18) throw new CoseError('not a tagged COSE_Sign1 (tag 18)');
  const a = t.value;
  if (!Array.isArray(a) || a.length !== 4) throw new CoseError('a COSE_Sign1 is an array of four');
  const [protectedBytes, unprotected, payload, signature] = a;
  if (!(protectedBytes instanceof Uint8Array)) throw new CoseError('the protected header is a byte string');
  if (!(unprotected instanceof Map)) throw new CoseError('the unprotected header is a map');
  if (!(payload === null || payload instanceof Uint8Array)) throw new CoseError('the payload is a byte string or null');
  if (!(signature instanceof Uint8Array)) throw new CoseError('the signature is a byte string');
  const prot = protectedBytes.length ? decode(protectedBytes) : new Map();
  if (!(prot instanceof Map)) throw new CoseError('the protected header is a map');
  return { protectedBytes, protected: prot, unprotected, payload, signature };
}

/** Sig_structure for COSE_Sign1 (RFC 9052 §4.4), empty external AAD. */
export const sigStructure = (protectedBytes, payload) => encode(['Signature1', protectedBytes, new Uint8Array(0), payload]);

const P256 = { name: 'ECDSA', namedCurve: 'P-256' };
async function es256Verify(jwk, protectedBytes, payload, signature) {
  if (signature.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, P256, false, ['verify']);
    return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, sigStructure(protectedBytes, payload));
  } catch {
    return false;
  }
}

/** An ES256 COSE_Sign1 over `payload`, signed with a WebCrypto P-256 private key. `detached` leaves payload null in the message. */
export async function signSign1({ protectedMap, unprotectedMap = new Map(), payload, privateKey, detached = false }) {
  const protectedBytes = encode(protectedMap);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, sigStructure(protectedBytes, payload)));
  return encode(new Tag(18, [protectedBytes, unprotectedMap, detached ? null : payload, signature]));
}

/* ------------------------------------------------------- Signed Statements */

const EMAIL = /[^\s@]+@[^\s@]+\.[^\s@]+/;

/**
 * Check a Signed Statement against our registration policy, short of the
 * signature (which needs the issuer's key). Returns the fields the log needs,
 * or throws CoseError naming the first rule it breaks.
 */
export function readStatement(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) throw new CoseError('send the Signed Statement as the request body (application/cose)');
  if (bytes.length > MAX_STATEMENT_BYTES) throw new CoseError(`a Signed Statement is at most ${MAX_STATEMENT_BYTES} bytes; its payload is a hash`);
  const s = parseSign1(bytes);
  const p = s.protected;
  if (p.get(LABEL.alg) !== ES256) throw new CoseError('the protected header must name ES256 (alg -7)');
  const kid = p.get(LABEL.kid);
  if (!(kid instanceof Uint8Array)) throw new CoseError('the protected header must carry kid (4): the id of a key you registered, as UTF-8 bytes');
  let keyId;
  try { keyId = td.decode(kid); } catch { keyId = ''; }
  if (!/^[0-9a-f]{16}$/.test(keyId)) throw new CoseError('kid must be the 16-character id of a key registered with POST /api/v2/evidence/keys');
  const cwt = p.get(LABEL.cwt);
  if (!(cwt instanceof Map)) throw new CoseError('the protected header must carry CWT claims (15) with iss (1) and sub (2)');
  const iss = cwt.get(1);
  const sub = cwt.get(2);
  if (typeof iss !== 'string' || iss.length < 1 || iss.length > 8192) throw new CoseError('iss (CWT claim 1) is text of 1 to 8192 characters');
  if (typeof sub !== 'string' || sub.length < 1 || sub.length > 1024) throw new CoseError('sub (CWT claim 2) is text of 1 to 1024 characters');
  if (EMAIL.test(iss) || EMAIL.test(sub)) throw new CoseError('iss and sub must not be email addresses: a statement names a subject, never a person');
  if (p.get(LABEL.payloadHashAlg) !== SHA256_ALG) throw new CoseError('the statement must be a hash envelope: protected 258 (payload hash alg) = -16 (SHA-256)');
  if (!(s.payload instanceof Uint8Array) || s.payload.length !== 32) throw new CoseError('the payload must be the 32-byte SHA-256 of your artifact, attached: the artifact itself never comes to us');
  if (s.signature.length !== 64) throw new CoseError('an ES256 signature is 64 bytes (r || s)');
  return { ...s, keyId, iss, sub };
}

/** The statement as it is registered: unprotected header emptied (a bstr, a0, bstr, bstr under tag 18). */
export const registeredStatement = (s) => encode(new Tag(18, [s.protectedBytes, new Map(), s.payload, s.signature]));

/** SHA-256 of the registered form, lowercase hex: the record_digest of its leaf. */
export const statementDigest = async (s) => hex(await sha256(registeredStatement(s)));

/** The issuer's signature on the statement, with the key its kid names. */
export const verifyStatementSignature = (s, jwk) => es256Verify(jwk, s.protectedBytes, s.payload, s.signature);

/* ---------------------------------------------------------------- receipts */

/**
 * The receipt's protected header. `leaf` is the v2 entry the log wrote.
 * The CWT sub is the statement digest; "riskrouter-leaf" carries the other
 * fields of the frozen leaf string, so a verifier can rebuild it.
 */
export function receiptProtected({ issuer, keyId, leaf, iat }) {
  return new Map([
    [LABEL.alg, ES256],
    [LABEL.kid, te.encode(keyId)],
    [LABEL.vds, RFC9162_SHA256],
    [LABEL.cwt, new Map([[1, issuer], [2, leaf.record_digest], [6, iat]])],
    ['riskrouter-profile', RECEIPT_PROFILE],
    ['riskrouter-leaf', [leaf.leaf_index, leaf.created_at, leaf.distributor_id, leaf.kind]]
  ]);
}

/** An RFC 9942 receipt of inclusion, detached root, signed with the log's P-256 key. */
export async function makeReceipt({ issuer, keyId, privateKey, leaf, treeSize, auditPath, rootHash, iat = Math.floor(Date.now() / 1000) }) {
  const proof = encode([treeSize, leaf.leaf_index, auditPath.map(unhex)]);
  return signSign1({
    protectedMap: receiptProtected({ issuer, keyId, leaf, iat }),
    unprotectedMap: new Map([[LABEL.vdp, new Map([[INCLUSION, [proof]]])]]),
    payload: unhex(rootHash),
    privateKey,
    detached: true
  });
}

/** RFC 9162 §2.1.3.2, returning the root the path leads to (or null). */
async function rootFromPath(index, size, leaf, path) {
  if (!Number.isInteger(index) || !Number.isInteger(size) || index < 0 || index >= size) return null;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of path) {
    if (sn === 0) return null;
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else {
      r = await nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 ? r : null;
}

/**
 * Verify a receipt: rebuild our leaf from its protected header, run the
 * inclusion proof to a root, and check the log's ES256 signature over that
 * root with the key its kid names from `keyring` (anchors/signing-key*.json).
 * With `statement` (the Signed Statement's bytes), also check the receipt is
 * for that statement. Returns { ok, reason | tree_size, leaf_index, root_hash, statement_digest, issuer, iat }.
 */
export async function verifyReceipt(receiptBytes, keyring, { statement } = {}) {
  let r;
  try { r = parseSign1(receiptBytes); } catch (e) { return { ok: false, reason: `not a receipt: ${e.message}` }; }
  const p = r.protected;
  if (p.get(LABEL.alg) !== ES256) return { ok: false, reason: 'the receipt is not ES256' };
  if (p.get(LABEL.vds) !== RFC9162_SHA256) return { ok: false, reason: 'the receipt is not for an RFC9162_SHA256 tree (vds 1)' };
  if (p.get('riskrouter-profile') !== RECEIPT_PROFILE) return { ok: false, reason: `the receipt is not ${RECEIPT_PROFILE}` };
  const cwt = p.get(LABEL.cwt);
  const fields = p.get('riskrouter-leaf');
  const digest = cwt instanceof Map ? cwt.get(2) : null;
  if (typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest) || !Array.isArray(fields) || fields.length !== 4) {
    return { ok: false, reason: 'the receipt does not carry the leaf it proves' };
  }
  const [leaf_index, created_at, distributor_id, kind] = fields;
  const proofs = r.unprotected.get(LABEL.vdp)?.get?.(INCLUSION);
  if (!Array.isArray(proofs) || proofs.length !== 1 || !(proofs[0] instanceof Uint8Array)) return { ok: false, reason: 'the receipt carries no single inclusion proof' };
  let proof;
  try { proof = decode(proofs[0]); } catch (e) { return { ok: false, reason: `the inclusion proof is not CBOR: ${e.message}` }; }
  if (!Array.isArray(proof) || proof.length !== 3 || !Array.isArray(proof[2]) || !proof[2].every((h) => h instanceof Uint8Array && h.length === 32)) {
    return { ok: false, reason: 'the inclusion proof is not [tree_size, leaf_index, [hash...]]' };
  }
  const [treeSize, proofIndex, path] = proof;
  if (proofIndex !== leaf_index) return { ok: false, reason: 'the inclusion proof is for another leaf than the receipt names' };
  const leaf = await leafHash(te.encode(leafString({ leaf_index, created_at, distributor_id, kind, record_digest: digest })));
  const root = await rootFromPath(leaf_index, treeSize, leaf, path.map(hex));
  if (!root) return { ok: false, reason: 'the inclusion proof does not lead to a root' };
  let kid;
  try { kid = td.decode(p.get(LABEL.kid) || new Uint8Array()); } catch { kid = ''; }
  const ring = Array.isArray(keyring) ? keyring : [keyring];
  const key = ring.find((k) => k.key_id === kid) || (ring.length === 1 && !ring[0].key_id ? ring[0] : null);
  if (!key) return { ok: false, reason: `signed with key ${kid || '(unnamed)'}, which is not among the keys you trust` };
  if (!await es256Verify(key.public_key, r.protectedBytes, unhex(root), r.signature)) {
    return { ok: false, reason: 'the log\'s signature over the root does not verify: the receipt was changed, or is not for this leaf' };
  }
  if (statement) {
    let s;
    try { s = parseSign1(statement); } catch (e) { return { ok: false, reason: `the statement is not a COSE_Sign1: ${e.message}` }; }
    if (await statementDigest(s) !== digest) return { ok: false, reason: 'the receipt is for another statement' };
  }
  return { ok: true, tree_size: treeSize, leaf_index, root_hash: root, statement_digest: digest, kind, issuer: cwt.get(1), iat: cwt.get(6) };
}

/** A Transparent Statement: the Signed Statement with its receipt(s) in unprotected header 394. */
export function transparentStatement(statementBytes, receipts) {
  const s = parseSign1(statementBytes);
  return encode(new Tag(18, [s.protectedBytes, new Map([[LABEL.receipts, receipts]]), s.payload, s.signature]));
}

/** Verify a Transparent Statement: every receipt it carries, each checked against the statement itself. */
export async function verifyTransparentStatement(bytes, keyring, { issuerKey } = {}) {
  let s;
  try { s = parseSign1(bytes); } catch (e) { return [{ ok: false, reason: `not a COSE_Sign1: ${e.message}` }]; }
  const receipts = s.unprotected.get(LABEL.receipts);
  if (!Array.isArray(receipts) || !receipts.length) return [{ ok: false, reason: 'no receipts in unprotected header 394' }];
  const statement = registeredStatement(s);
  const out = [];
  for (const rc of receipts) out.push(await verifyReceipt(rc, keyring, { statement }));
  if (issuerKey) {
    out.push(await es256Verify(issuerKey, s.protectedBytes, s.payload, s.signature)
      ? { ok: true, issuer_signature: true } : { ok: false, reason: 'the issuer\'s signature on the statement does not verify with the key given' });
  }
  return out;
}
