#!/usr/bin/env node
/**
 * RFC 3161 time-stamp tokens on our signed heads. Design: docs/legal-time.md.
 *
 *   node tools/tsa.mjs stamp  [--api https://api.riskrouter.eu] [--dry-run]
 *   node tools/tsa.mjs verify <file.json>... [--key <key file or directory>]
 *
 * `stamp` fetches the current v2 evidence head and the current v1 attestation,
 * checks our signature on each against anchors/signing-key.json, and asks every
 * authority in anchors/tsa/authorities.json for a token over
 * SHA-256(UTF-8(signed payload)). Each token is verified before it is written,
 * a head already stamped by an authority is skipped, and no file is ever
 * overwritten. `verify` checks files offline.
 *
 * ---------------------------------------------------------------------------
 * Why this lives in tools/ and not in the Worker
 *
 * Rule 1: no stranger's request can cause this call. It runs hourly from
 * .github/workflows/timestamp.yml, about heads that are already public; the
 * Worker contacts nothing new. Same basis as tools/timestamp.mjs.
 *
 * ---------------------------------------------------------------------------
 * What a token proves, and what "qualified" means here
 *
 * An RFC 3161 token is the authority's signed statement that it saw this exact
 * digest at genTime. Under eIDAS a *qualified* time stamp additionally carries
 * a legal presumption of accurate time and integrity (Regulation (EU) No
 * 910/2014, Article 41). Only an authority the operator has contracted and
 * listed with its EU Trusted List entry is called qualified; the free public
 * authorities are not, and every report says so.
 *
 * Offline verification covers the imprint, the signed attributes, the
 * signature with the certificate the token carries, that certificate's
 * time-stamping purpose and validity at genTime, and the chain the token
 * carries. Whether the chain's root is the authority's own is checked against
 * the root the authority publishes: the command is printed.
 *
 * Standard-library Node only.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { loadKeyring, pickKey } from './keyring.mjs';
import { headPayload } from './merkle.mjs';

export const TIMESTAMP_FORMAT = 'riskrouter-head-timestamp|1';
const HERE = path.dirname(fileURLToPath(import.meta.url));
export const TSA_DIR = path.join(HERE, '..', 'anchors', 'tsa');

const OID = {
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingCertificate: '1.2.840.113549.1.9.16.2.12',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
  timeStamping: '1.3.6.1.5.5.7.3.8',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  sha1: '1.3.14.3.2.26'
};
const HASHES = { [OID.sha256]: 'sha256', [OID.sha384]: 'sha384', [OID.sha512]: 'sha512' };
const SIG_ALGS = {
  '1.2.840.113549.1.1.1': null,            // rsaEncryption: the hash is the digestAlgorithm
  '1.2.840.113549.1.1.11': 'sha256', '1.2.840.113549.1.1.12': 'sha384', '1.2.840.113549.1.1.13': 'sha512',
  '1.2.840.10045.4.3.2': 'sha256', '1.2.840.10045.4.3.3': 'sha384', '1.2.840.10045.4.3.4': 'sha512'
};

/* -------------------------------------------------------------------- DER */

export function readTlv(buf, pos = 0) {
  const start = pos;
  if (pos >= buf.length) throw new Error('DER: read past the end');
  const tag = buf[pos++];
  if ((tag & 0x1f) === 0x1f) throw new Error('DER: high tag numbers are not used by RFC 3161');
  let len = buf[pos++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('DER: indefinite or oversized length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[pos++];
  }
  const end = pos + len;
  if (end > buf.length) throw new Error('DER: truncated');
  return { tag, start, valueStart: pos, end };
}
export function children(buf, node) {
  const out = [];
  for (let p = node.valueStart; p < node.end;) { const c = readTlv(buf, p); out.push(c); p = c.end; }
  return out;
}
const whole = (buf, n) => buf.subarray(n.start, n.end);
const inner = (buf, n) => buf.subarray(n.valueStart, n.end);
function expect(n, tag, what) {
  if (!n || n.tag !== tag) throw new Error(`token: ${what} is not where RFC 3161 puts it`);
  return n;
}
export function oidString(bytes) {
  const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let v = 0;
  for (const b of bytes.subarray(1)) { v = v * 128 + (b & 0x7f); if (!(b & 0x80)) { parts.push(v); v = 0; } }
  return parts.join('.');
}
const hexInt = (bytes) => Buffer.from(bytes).toString('hex').replace(/^0+(?=.)/, '');
function generalizedTime(s) {
  const m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/);
  if (!m) throw new Error(`token: genTime ${s} is not a UTC GeneralizedTime`);
  return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] || ''}Z`;
}

function tlv(tag, content) {
  const len = content.length;
  const head = len < 128 ? Buffer.from([tag, len])
    : len < 256 ? Buffer.from([tag, 0x81, len]) : Buffer.from([tag, 0x82, len >> 8, len & 0xff]);
  return Buffer.concat([head, content]);
}
function derOid(s) {
  const p = s.split('.').map(Number);
  const out = [40 * p[0] + p[1]];
  for (const v of p.slice(2)) {
    const stack = [v & 0x7f];
    for (let x = Math.floor(v / 128); x > 0; x = Math.floor(x / 128)) stack.unshift((x & 0x7f) | 0x80);
    out.push(...stack);
  }
  return tlv(0x06, Buffer.from(out));
}
/** A non-negative INTEGER in minimal DER: no redundant leading zero, one added when the top bit is set. */
export function derInt(bytes) {
  let b = Buffer.from(bytes);
  while (b.length > 1 && b[0] === 0x00) b = b.subarray(1);     // a random nonce may start with zero bytes
  return tlv(0x02, b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b);
}

/** TimeStampReq: v1, SHA-256 imprint, a nonce, and certReq so the token carries the authority's certificate. */
export function buildRequest(imprint, nonce) {
  return tlv(0x30, Buffer.concat([
    derInt(Buffer.from([1])),
    tlv(0x30, Buffer.concat([tlv(0x30, Buffer.concat([derOid(OID.sha256), Buffer.from([0x05, 0x00])])), tlv(0x04, imprint)])),
    derInt(nonce),
    Buffer.from([0x01, 0x01, 0xff])
  ]));
}

/** TimeStampResp: the status, and the token when granted. */
export function parseResponse(der) {
  const buf = Buffer.from(der);
  const top = children(buf, expect(readTlv(buf), 0x30, 'the response'));
  const status = children(buf, expect(top[0], 0x30, 'the status'));
  const code = Number.parseInt(hexInt(inner(buf, expect(status[0], 0x02, 'the status code'))), 16);
  if (code !== 0 && code !== 1) {
    const text = status[1]?.tag === 0x30 ? children(buf, status[1]).map((s) => inner(buf, s).toString('utf8')).join('; ') : '';
    throw new Error(`the authority refused (status ${code}${text ? `: ${text}` : ''})`);
  }
  if (!top[1]) throw new Error('the authority granted but sent no token');
  return Buffer.from(whole(buf, top[1]));
}

/* ----------------------------------------------------------------- verify */

function attributes(buf, node) {
  const out = new Map();
  for (const a of children(buf, node)) {
    const [type, values] = children(buf, a);
    out.set(oidString(inner(buf, type)), children(buf, values).map((v) => ({ node: v, buf })));
  }
  return out;
}

const sameSerial = (a, b) => a.toLowerCase().replace(/^0+(?=.)/, '') === b.toLowerCase().replace(/^0+(?=.)/, '');

/** The chain the token carries, from the signer upwards, as far as it goes. */
function chainOf(signer, certs) {
  const chain = [signer];
  for (let current = signer; chain.length < 8;) {
    if (current.checkIssued(current) && current.verify(current.publicKey)) break;     // a self-signed root
    const up = certs.find((c) => c !== current && !chain.includes(c) && current.checkIssued(c) && current.verify(c.publicKey));
    if (!up) break;
    chain.push(up);
    current = up;
  }
  const top = chain.at(-1);
  return {
    certificates: chain.map((c) => ({ subject: c.subject.replace(/\n/g, ', '), fingerprint256: c.fingerprint256 })),
    root_self_signed: top.checkIssued(top) && top.verify(top.publicKey)
  };
}

/**
 * Verify a TimeStampToken (DER) against the imprint it should carry.
 * Returns { ok: true, gen_time, ... } or { ok: false, reason }.
 */
export function verifyToken(tokenDer, imprint, { nonce } = {}) {
  try {
    const buf = Buffer.from(tokenDer);
    const ci = children(buf, expect(readTlv(buf), 0x30, 'the token'));
    if (oidString(inner(buf, expect(ci[0], 0x06, 'the content type'))) !== OID.signedData) return { ok: false, reason: 'the token is not CMS SignedData' };
    const sd = children(buf, expect(children(buf, expect(ci[1], 0xa0, 'the signed data'))[0], 0x30, 'the signed data'));
    const encap = children(buf, expect(sd[2], 0x30, 'the encapsulated content'));
    if (oidString(inner(buf, encap[0])) !== OID.tstInfo) return { ok: false, reason: 'the signed content is not a TSTInfo' };
    const eContent = inner(buf, expect(children(buf, expect(encap[1], 0xa0, 'the content'))[0], 0x04, 'the content'));
    const certNode = sd.find((n, i) => i > 2 && n.tag === 0xa0);
    const signerInfos = sd.at(-1);
    expect(signerInfos, 0x31, 'the signer infos');

    // The TSTInfo: what the authority says it saw, and when.
    const tb = Buffer.from(eContent);
    const tst = children(tb, expect(readTlv(tb), 0x30, 'the TSTInfo'));
    const policy = oidString(inner(tb, tst[1]));
    const mi = children(tb, expect(tst[2], 0x30, 'the message imprint'));
    const miAlg = oidString(inner(tb, children(tb, mi[0])[0]));
    if (miAlg !== OID.sha256) return { ok: false, reason: `the imprint uses ${miAlg}, not SHA-256` };
    if (!Buffer.from(inner(tb, mi[1])).equals(Buffer.from(imprint))) {
      return { ok: false, reason: 'the token is for a different digest: it does not timestamp this payload' };
    }
    const serial = hexInt(inner(tb, tst[3]));
    const genTime = generalizedTime(inner(tb, expect(tst[4], 0x18, 'genTime')).toString('ascii'));
    const nonceNode = tst.slice(5).find((n) => n.tag === 0x02);
    const tokenNonce = nonceNode ? hexInt(inner(tb, nonceNode)) : null;
    if (nonce && tokenNonce !== hexInt(nonce)) return { ok: false, reason: 'the token does not carry the nonce we sent' };

    // The signer, and what it signed.
    const infos = children(buf, signerInfos);
    if (infos.length !== 1) return { ok: false, reason: `the token has ${infos.length} signers, not one` };
    const si = children(buf, infos[0]);
    const sid = si[1];
    const digestAlg = oidString(inner(buf, children(buf, si[2])[0]));
    const hash = HASHES[digestAlg];
    if (!hash) return { ok: false, reason: digestAlg === OID.sha1 ? 'SHA-1 is not accepted' : `unsupported digest ${digestAlg}` };
    const attrsNode = expect(si[3], 0xa0, 'the signed attributes');
    const attrs = attributes(buf, attrsNode);
    const ct = attrs.get(OID.contentType);
    if (!ct || oidString(inner(buf, ct[0].node)) !== OID.tstInfo) return { ok: false, reason: 'the signed attributes do not say the content is a TSTInfo' };
    const md = attrs.get(OID.messageDigest);
    if (!md || !Buffer.from(inner(buf, md[0].node)).equals(crypto.createHash(hash).update(eContent).digest())) {
      return { ok: false, reason: 'the signed attributes do not bind this TSTInfo: it was changed after signing' };
    }
    const sigAlgOid = oidString(inner(buf, children(buf, si[4])[0]));
    if (!(sigAlgOid in SIG_ALGS)) return { ok: false, reason: `unsupported signature algorithm ${sigAlgOid}` };
    const sigHash = SIG_ALGS[sigAlgOid] || hash;
    const signature = inner(buf, expect(si[5], 0x04, 'the signature'));

    const certs = certNode ? children(buf, certNode).filter((c) => c.tag === 0x30).map((c) => new crypto.X509Certificate(whole(buf, c))) : [];
    let candidates;
    if (sid.tag === 0x30) {
      const [, serialNode] = children(buf, sid);
      const want = hexInt(inner(buf, serialNode));
      candidates = certs.filter((c) => sameSerial(c.serialNumber, want));
    } else {
      candidates = certs;       // [0] subjectKeyIdentifier: the signature check below picks the one
    }
    // DER of the signed attributes, re-tagged as the SET they are (RFC 5652 §5.4).
    const signedBytes = Buffer.from(whole(buf, attrsNode)); signedBytes[0] = 0x31;
    const signer = candidates.find((c) => {
      try { return crypto.verify(sigHash, signedBytes, c.publicKey, signature); } catch { return false; }
    });
    if (!signer) {
      return { ok: false, reason: certs.length ? 'the authority\'s signature does not verify with the certificate the token carries' : 'the token carries no certificate to check its signature with' };
    }
    // ESS signing-certificate: binds the signature to this certificate (RFC 5816).
    const ess = attrs.get(OID.signingCertificateV2) || attrs.get(OID.signingCertificate);
    if (ess) {
      const v2 = attrs.has(OID.signingCertificateV2);
      const first = children(buf, children(buf, ess[0].node)[0])[0];
      const certId = children(buf, first);
      let essHash = v2 ? 'sha256' : 'sha1';
      let hashNode = certId[0];
      if (v2 && certId[0].tag === 0x30) { essHash = HASHES[oidString(inner(buf, children(buf, certId[0])[0]))] || 'unsupported'; hashNode = certId[1]; }
      if (essHash === 'unsupported' || !Buffer.from(inner(buf, hashNode)).equals(crypto.createHash(essHash).update(signer.raw).digest())) {
        return { ok: false, reason: 'the signing-certificate attribute names a different certificate' };
      }
    }
    if (!(signer.keyUsage || []).includes(OID.timeStamping)) {
      return { ok: false, reason: 'the signing certificate is not for time-stamping (no id-kp-timeStamping)' };
    }
    const at = new Date(genTime);
    if (at < new Date(signer.validFrom) || at > new Date(signer.validTo)) {
      return { ok: false, reason: 'genTime is outside the signing certificate\'s validity' };
    }
    return {
      ok: true, gen_time: genTime, policy, serial, nonce: tokenNonce,
      tsa: { subject: signer.subject.replace(/\n/g, ', '), issuer: signer.issuer.replace(/\n/g, ', '), fingerprint256: signer.fingerprint256 },
      chain: chainOf(signer, certs)
    };
  } catch (error) {
    return { ok: false, reason: `the token cannot be read: ${error.message}` };
  }
}

/* ------------------------------------------------------ heads and files */

export const attestationPayload = (a) => ['riskrouter-ledger-attestation', 'v1', String(a.as_of), String(a.entries), String(a.head_hash)].join('|');

/** The subject a response describes: which frozen payload, and the file name part. */
export function subjectOf(body) {
  if (body?.head) return { subject: 'riskrouter-evidence-head|v2', name: `evidence-head-${Number(body.head.tree_size)}`, payload: headPayload(body.head), signed: { head: body.head } };
  if (body?.attestation) return { subject: 'riskrouter-ledger-attestation|v1', name: `ledger-${Number(body.attestation.entries)}`, payload: attestationPayload(body.attestation), signed: { attestation: body.attestation } };
  return null;
}

function verifyOurSignature(ring, payload, signature) {
  if (!signature?.signature) return { ok: false, reason: 'the head carries no signature; an unsigned head is not timestamped' };
  if (signature.signed_payload && signature.signed_payload !== payload) return { ok: false, reason: 'our signature covers different content than the head claims' };
  const key = pickKey(ring, signature.key_id);
  if (!key) return { ok: false, reason: `signed with key ${signature.key_id || '(unnamed)'}, which is not among the keys supplied` };
  try {
    const pub = crypto.createPublicKey({ key: key.public_key, format: 'jwk' });
    return crypto.verify('sha256', Buffer.from(payload, 'utf8'), { key: pub, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature.signature, 'base64'))
      ? { ok: true } : { ok: false, reason: 'our signature on the head does not verify' };
  } catch {
    return { ok: false, reason: 'our signature on the head cannot be read' };
  }
}

const QUALIFIED_LIST = /^https:\/\/(eidas\.ec\.europa\.eu|esignature\.ec\.europa\.eu)\//;

/** One timestamp file, offline. Returns lines of { ok | failed | skipped | note }. */
export function verifyTimestampFile(doc, ring = null) {
  const lines = [];
  if (doc?.format !== TIMESTAMP_FORMAT) return [{ failed: `not a ${TIMESTAMP_FORMAT} file` }];
  const s = subjectOf(doc.signed);
  if (!s || s.subject !== doc.subject || s.payload !== doc.payload) {
    return [{ failed: 'the payload is not the one the head it carries produces' }];
  }
  if (ring) {
    const sig = verifyOurSignature(ring, doc.payload, doc.signature);
    lines.push(sig.ok ? { ok: 'our signature on the head verifies' } : { failed: sig.reason });
  } else {
    lines.push({ skipped: 'our signature on the head: no key supplied (--key)' });
  }
  const imprint = crypto.createHash('sha256').update(doc.payload, 'utf8').digest();
  const r = verifyToken(Buffer.from(String(doc.token || ''), 'base64'), imprint);
  if (!r.ok) return [...lines, { failed: `RFC 3161 token: ${r.reason}` }];
  if (doc.gen_time && doc.gen_time !== r.gen_time) lines.push({ failed: `the file says ${doc.gen_time} but the token says ${r.gen_time}` });
  lines.push({ ok: `RFC 3161 token: ${doc.tsa?.name || r.tsa.subject} states it saw this head at ${r.gen_time}` });
  lines.push({ ok: `signed by ${r.tsa.subject}, a time-stamping certificate valid at that time` });
  const root = r.chain.certificates.at(-1);
  lines.push({
    note: r.chain.root_self_signed
      ? `chain carried in the token ends at the self-signed root ${root.subject} (SHA-256 ${root.fingerprint256}); compare it with the root the authority publishes, or run: openssl ts -verify -data <payload file> -in <token.tsr> -CAfile <authority root>`
      : `chain carried in the token ends at ${root.subject}, whose issuer is not in the token; check it against the authority's published chain with openssl ts -verify`
  });
  if (doc.tsa?.qualified === true) {
    lines.push(QUALIFIED_LIST.test(String(doc.tsa.trusted_list || ''))
      ? { note: `listed by the operator as a qualified eIDAS time stamp; check the authority's entry: ${doc.tsa.trusted_list}` }
      : { failed: 'the file calls this a qualified time stamp but names no EU Trusted List entry' });
  } else {
    lines.push({ note: 'not a qualified eIDAS time stamp: admissible evidence of time, without the legal presumption Article 41(2) gives a qualified one' });
  }
  return lines;
}

/* ------------------------------------------------------------------ stamp */

/**
 * What an authority may be asked to stamp. A paid authority can be limited to the
 * evidence head alone (`"subjects": ["evidence-head"]`), so at most one token an hour
 * is bought, whatever happens to the v1 ledger. Absent, it stamps both.
 */
export const SUBJECT_KINDS = ['evidence-head', 'ledger'];
const kindOf = (name) => name.replace(/-\d+$/, '');

export function loadAuthorities(dir = TSA_DIR) {
  const list = JSON.parse(fs.readFileSync(path.join(dir, 'authorities.json'), 'utf8')).authorities;
  for (const a of list) {
    if (!/^[a-z0-9-]{2,32}$/.test(a.id)) throw new Error(`authority id ${a.id} is not a short lower-case id`);
    if (a.qualified === true && !QUALIFIED_LIST.test(String(a.trusted_list || ''))) {
      throw new Error(`authority ${a.id} is marked qualified without an EU Trusted List entry`);
    }
    if (a.subjects !== undefined && (!Array.isArray(a.subjects) || !a.subjects.length || a.subjects.some((x) => !SUBJECT_KINDS.includes(x)))) {
      throw new Error(`authority ${a.id}: subjects must be a non-empty list of ${SUBJECT_KINDS.join(', ')}`);
    }
    if (a.auth_env !== undefined && !/^[A-Z][A-Z0-9_]{2,63}$/.test(String(a.auth_env))) {
      throw new Error(`authority ${a.id}: auth_env must name an environment variable`);
    }
  }
  return list;
}

/** Ask one authority for a token over the payload, and verify it before returning. */
export async function requestToken(authority, payload, { fetchImpl = fetch, env = process.env } = {}) {
  const imprint = crypto.createHash('sha256').update(payload, 'utf8').digest();
  const nonce = crypto.randomBytes(8);
  const headers = { 'Content-Type': 'application/timestamp-query', Accept: 'application/timestamp-reply' };
  if (authority.auth_env && env[authority.auth_env]) headers.Authorization = `Basic ${Buffer.from(env[authority.auth_env]).toString('base64')}`;
  const response = await fetchImpl(authority.url, { method: 'POST', headers, body: buildRequest(imprint, nonce), signal: AbortSignal.timeout(20000) });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const token = parseResponse(Buffer.from(await response.arrayBuffer()));
  const r = verifyToken(token, imprint, { nonce });
  if (!r.ok) throw new Error(`the token does not verify: ${r.reason}`);
  return { token, check: r };
}

/**
 * Stamp the current heads. `fetchJson(path)` returns a parsed API body.
 * Returns lines; throws only on an alarm (a second head for one size).
 */
export async function stamp({ fetchJson, ring, authorities, dir = TSA_DIR, now = () => new Date(), dryRun = false, fetchImpl, env } = {}) {
  const lines = [];
  for (const route of ['/api/v2/evidence/head', '/api/v1/ledger/attestation']) {
    let body;
    try { body = await fetchJson(route); } catch (e) { lines.push({ warn: `${route}: could not be read (${e.message})` }); continue; }
    const s = subjectOf(body);
    if (!s) { lines.push({ warn: `${route}: not a head` }); continue; }
    const sig = verifyOurSignature(ring, s.payload, body.signature);
    if (!sig.ok) { lines.push({ warn: `${route}: ${sig.reason}; nothing timestamped` }); continue; }
    for (const a of authorities) {
      if (a.subjects && !a.subjects.includes(kindOf(s.name))) continue;
      const file = path.join(dir, `${s.name}.${a.id}.json`);
      if (fs.existsSync(file)) {
        const held = JSON.parse(fs.readFileSync(file, 'utf8'));
        const heldRoot = held.signed.head?.root_hash ?? held.signed.attestation?.head_hash;
        const nowRoot = s.signed.head?.root_hash ?? s.signed.attestation?.head_hash;
        if (heldRoot !== nowRoot) {
          const e = new Error(`ALARM: ${s.name} was timestamped with root ${heldRoot} and is now served with ${nowRoot}. Two heads for one size is a rewritten history.`);
          e.alarm = true;
          throw e;
        }
        lines.push({ skipped: `${s.name}: already timestamped by ${a.id}` });
        continue;
      }
      if (dryRun) { lines.push({ skipped: `${s.name}: would ask ${a.id}` }); continue; }
      // A contracted authority is never called without its credentials: no anonymous use of a paid service.
      if (a.auth_env && !(env ?? process.env)[a.auth_env]) { lines.push({ warn: `${s.name}: ${a.id} not asked, its credentials (${a.auth_env}) are not set` }); continue; }
      try {
        const { token, check } = await requestToken(a, s.payload, { fetchImpl, env });
        const doc = {
          format: TIMESTAMP_FORMAT, subject: s.subject, signed: s.signed, signature: body.signature, payload: s.payload,
          tsa: { id: a.id, name: a.name, url: a.url, qualified: a.qualified === true, trusted_list: a.trusted_list || null },
          token: token.toString('base64'), gen_time: check.gen_time, requested_at: now().toISOString()
        };
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(file, JSON.stringify(doc, null, 2) + '\n', { flag: 'wx' });     // never overwrite
        lines.push({ ok: `${s.name}: ${a.id} timestamped it at ${check.gen_time}` });
      } catch (e) {
        lines.push({ warn: `${s.name}: ${a.id} gave no usable token (${e.message})` });
      }
    }
  }
  return lines;
}

/** Every timestamp file in the directory, for the site's figures. */
export function readTimestamps(dir = TSA_DIR) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => /^(evidence-head|ledger)-\d+\.[a-z0-9-]+\.json$/.test(f)).sort()
    .map((f) => ({ file: f, ...JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')) }));
}

/* -------------------------------------------------------------------- cli */

function opt(args, name) {
  const i = args.indexOf(name);
  if (i === -1) return { value: undefined, rest: args };
  return { value: args[i + 1], rest: [...args.slice(0, i), ...args.slice(i + 2)] };
}
const show = (l) => l.ok ? `OK    ${l.ok}` : l.failed ? `FAIL  ${l.failed}` : l.warn ? `WARN  ${l.warn}` : l.note ? `NOTE  ${l.note}` : `SKIP  ${l.skipped}`;

async function main() {
  const [mode, ...argv] = process.argv.slice(2);
  const apiOpt = opt(argv, '--api'); const keyOpt = opt(apiOpt.rest, '--key');
  const dry = keyOpt.rest.includes('--dry-run');
  const files = keyOpt.rest.filter((a) => a !== '--dry-run');
  try {
    if (mode === 'stamp') {
      const api = (apiOpt.value || 'https://api.riskrouter.eu').replace(/\/$/, '');
      const fetchJson = async (p) => {
        const r = await fetch(api + p, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(20000) });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      };
      const lines = await stamp({ fetchJson, ring: loadKeyring(keyOpt.value), authorities: loadAuthorities(), dryRun: dry });
      for (const l of lines) console.log(show(l));
      // A warning is surfaced to the workflow; only an alarm fails it.
      for (const l of lines.filter((x) => x.warn)) console.log(`::warning::${l.warn}`);
    } else if (mode === 'verify') {
      if (!files.length) throw new Error('usage: node tools/tsa.mjs verify <file.json>... [--key <file|dir>]');
      const ring = keyOpt.value ? loadKeyring(keyOpt.value) : null;
      let failed = false;
      for (const f of files) {
        console.log(f);
        for (const l of verifyTimestampFile(JSON.parse(fs.readFileSync(f, 'utf8')), ring)) { console.log(`  ${show(l)}`); failed ||= Boolean(l.failed); }
      }
      process.exit(failed ? 1 : 0);
    } else {
      console.error('usage: node tools/tsa.mjs stamp [--api URL] [--key <file|dir>] [--dry-run] | verify <file.json>... [--key <file|dir>]');
      process.exit(2);
    }
  } catch (error) {
    console.error(`${error.alarm ? '' : 'FAIL  '}${error.message}`);
    if (error.alarm) console.log(`::error::${error.message}`);
    process.exit(1);
  }
}

if (process.argv[1] && process.argv[1].endsWith('tsa.mjs')) main();
