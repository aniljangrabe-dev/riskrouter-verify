#!/usr/bin/env node
/**
 * Completeness chains and spot checks: is this all of it, and was it kept?
 * Design and reasoning: docs/completeness.md and docs/spot-checks.md.
 *
 *   node chains.mjs tag     --secret <hex> --name <chain name>          a chain_tag nobody can guess
 *   node chains.mjs select  --seed <block hash> --population <n> --sample <k>
 *   node chains.mjs check   <file.json> [--key <key file or directory>]
 *
 * check reads a chain statement (riskrouter-evidence-chain|v1, as
 * GET /api/v2/evidence/chain returns it), a completeness bundle
 * (riskrouter-completeness-bundle|1: the statement and every record in the
 * chain) or a spot-check bundle (riskrouter-spot-check-bundle|1: the
 * statement, the seed and the records the seed selects).
 *
 * The spot-check selection (frozen from the first published vectors):
 *
 *   for counter = 0, 1, 2, ...
 *     h = SHA-256(UTF-8("riskrouter-spot-check|v1|" seed "|" population "|" counter))
 *     x = the first 8 bytes of h, big-endian, as an unsigned 64-bit integer
 *     skip x if x >= 2^64 - (2^64 mod population)          (no bias towards low positions)
 *     position = 1 + (x mod population); keep it unless already drawn
 *   until min(sample, population) positions are drawn, in draw order.
 *
 * The seed is the hash of a Bitcoin block whose height the auditor announced,
 * and sealed in the log, before it was mined: neither the firm nor the
 * auditor can choose which records come up.
 *
 * Standard-library Node only, so this file can be copied anywhere and run.
 */
import fs from 'node:fs';
import crypto from 'node:crypto';
import { chainPayload, linksDigest, headPayload, CHAIN_FORMAT, CHAIN_GENESIS } from './merkle.mjs';
import { recordDigest } from './records.mjs';
import { pickKey } from './keyring.mjs';

export const COMPLETENESS_FORMAT = 'riskrouter-completeness-bundle|1';
export const SPOT_CHECK_FORMAT = 'riskrouter-spot-check-bundle|1';
export { CHAIN_FORMAT, CHAIN_GENESIS };

const HEX64 = /^[0-9a-f]{64}$/;
const SECRET = /^(?:[0-9a-f]{2}){16,64}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const TWO64 = 1n << 64n;

/** A chain_tag derived from a secret the firm keeps: HMAC-SHA256(secret, "riskrouter-chain-tag|1|" || name). */
export function chainTag(secretHex, name) {
  if (typeof secretHex !== 'string' || !SECRET.test(secretHex)) throw new Error('the chain secret is 16 to 64 bytes written as lowercase hex');
  if (typeof name !== 'string' || !name) throw new Error('a chain has a name');
  return crypto.createHmac('sha256', Buffer.from(secretHex, 'hex')).update(`riskrouter-chain-tag|1|${name}`, 'utf8').digest('hex');
}

/** The positions (1-based) a seed selects from a population, in draw order. Frozen. */
export function selectSample(seed, population, sample) {
  if (typeof seed !== 'string' || !HEX64.test(seed)) throw new Error('the seed is a block hash: 64 lowercase hex characters');
  if (!Number.isSafeInteger(population) || population < 1) throw new Error('the population is a whole number of at least 1');
  if (!Number.isSafeInteger(sample) || sample < 1) throw new Error('the sample is a whole number of at least 1');
  const n = BigInt(population);
  const limit = TWO64 - (TWO64 % n);
  const want = Math.min(sample, population);
  const drawn = [];
  const seen = new Set();
  for (let counter = 0; drawn.length < want; counter++) {
    const h = crypto.createHash('sha256').update(`riskrouter-spot-check|v1|${seed}|${population}|${counter}`, 'utf8').digest();
    const x = h.readBigUInt64BE(0);
    if (x >= limit) continue;
    const position = Number(x % n) + 1;
    if (!seen.has(position)) { seen.add(position); drawn.push(position); }
  }
  return drawn;
}

function verifyP256(published, payload, signatureB64) {
  try {
    const key = crypto.createPublicKey({ key: published.public_key, format: 'jwk' });
    return crypto.verify('sha256', Buffer.from(payload, 'utf8'), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(String(signatureB64), 'base64'));
  } catch {
    return false;
  }
}

function signatureLine(ring, payload, signature, what) {
  if (!ring) return { skipped: `${what}: no key supplied (--key), signature not checked` };
  if (!signature) return { failed: `${what}: carries no signature` };
  if (signature.signed_payload && signature.signed_payload !== payload) return { failed: `${what}: the signature covers different content than the file claims` };
  const published = pickKey(ring, signature.key_id);
  if (!published) return { failed: `${what}: signed with key ${signature.key_id || '(unnamed)'}, which is not among the keys supplied` };
  return verifyP256(published, payload, signature.signature) ? { ok: `${what}: signature verifies (key ${published.key_id || '(unnamed)'})` }
    : { failed: `${what}: the signature does not verify against the key supplied` };
}

/**
 * One chain statement on its own: its links are contiguous and well formed,
 * they produce links_digest, and the log signed it (and the head it names).
 * Returns { lines, ok, links } where links maps chain_seq to its link.
 */
export async function verifyChainStatement(doc, ring) {
  const lines = [];
  const links = new Map();
  const fail = (m) => { lines.push({ failed: `chain: ${m}` }); return { lines, ok: false, links }; };
  if (!doc || doc.format !== CHAIN_FORMAT) return fail(`not a ${CHAIN_FORMAT} statement`);
  if (!HEX64.test(String(doc.chain_tag))) return fail('chain_tag is not 64 lowercase hex characters');
  const { length, from, to } = doc;
  if (![length, from, to].every(Number.isSafeInteger) || length < 0 || from < 1 || to < from - 1 || to > length) {
    return fail('length, from and to are not a range within the chain');
  }
  if (!doc.head || !Number.isSafeInteger(Number(doc.head.tree_size)) || !HEX64.test(String(doc.head.root_hash))) return fail('carries no head');
  const list = Array.isArray(doc.links) ? doc.links : [];
  if (list.length !== to - from + 1) return fail(`lists ${list.length} links for positions ${from} to ${to}`);
  for (const [i, l] of list.entries()) {
    if (l?.chain_seq !== from + i) return fail(`link ${i} is position ${l?.chain_seq}, expected ${from + i}: the links are not contiguous`);
    if (!Number.isSafeInteger(l.leaf_index) || l.leaf_index < 0 || l.leaf_index >= Number(doc.head.tree_size)) return fail(`position ${l.chain_seq} names a leaf outside the head's tree`);
    if (!TIME.test(String(l.created_at)) || !HEX64.test(String(l.record_digest))) return fail(`position ${l.chain_seq} is not a well-formed link`);
    if (i > 0 && !(l.leaf_index > list[i - 1].leaf_index)) return fail(`position ${l.chain_seq} is not later in the log than the one before it`);
    links.set(l.chain_seq, l);
  }
  const digest = await linksDigest(list);
  if (digest !== doc.links_digest) return fail('the links do not produce links_digest: the list was changed');
  lines.push({ ok: `chain: ${doc.chain_tag.slice(0, 12)}… has ${length} record${length === 1 ? '' : 's'} as of tree size ${doc.head.tree_size}; positions ${from}–${to} listed and intact` });
  lines.push(doc.chain_signature ? signatureLine(ring, chainPayload(doc), doc.chain_signature, 'chain statement')
    : { failed: `chain statement: unsigned${doc.chain_signature_unavailable ? ` (${doc.chain_signature_unavailable})` : ''}` });
  if (doc.signature) lines.push(signatureLine(ring, headPayload(doc.head), doc.signature, 'evidence head'));
  return { lines, ok: !lines.some((l) => l.failed), links };
}

/** Several pages of one chain, read as one: same tag, same head, same length. */
async function readStatements(pages, ring) {
  const lines = [];
  const links = new Map();
  const docs = Array.isArray(pages) ? pages : pages ? [pages] : [];
  if (!docs.length) return { lines: [{ failed: 'carries no chain statement' }], ok: false };
  const first = docs[0];
  for (const d of docs) {
    const r = await verifyChainStatement(d, ring);
    lines.push(...r.lines);
    if (d !== first && (d.chain_tag !== first.chain_tag || d.length !== first.length || d.head?.tree_size !== first.head?.tree_size || d.head?.root_hash !== first.head?.root_hash)) {
      lines.push({ failed: 'chain: the pages are not one statement (another tag, head or length)' });
    }
    for (const [seq, l] of r.links) links.set(seq, l);
  }
  return { lines, ok: !lines.some((l) => l.failed), links, tag: first.chain_tag, length: first.length, head: first.head };
}

/** Index the records shown by their digest. */
function indexRecords(records, lines) {
  const byDigest = new Map();
  for (const [i, r] of (Array.isArray(records) ? records : []).entries()) {
    try {
      byDigest.set(recordDigest(r.salt_hex, r.record), r.record);
    } catch (e) {
      lines.push({ failed: `record ${i}: ${e.message}` });
    }
  }
  return byDigest;
}

/** The record at position seq: shown, the one sealed, and carrying its place in the chain. */
function checkPosition(seq, link, tag, byDigest, previous) {
  const record = byDigest.get(link.record_digest);
  if (!record) return { failed: `position ${seq}: not shown. The log holds a record here (leaf ${link.leaf_index}, sealed ${link.created_at}).` };
  if (record.chain_tag !== tag || record.chain_seq !== seq) {
    return { failed: `position ${seq}: the record shown says it is ${record.chain_tag === tag ? `position ${record.chain_seq}` : 'in another chain'}` };
  }
  if (previous !== undefined && record.chain_prev !== previous) {
    return { failed: `position ${seq}: chain_prev is not the digest of position ${seq - 1}` };
  }
  return { ok: `position ${seq}: shown, and it is the record sealed (leaf ${link.leaf_index})` };
}

/**
 * Every record of the chain, as of the statement's head (or as of a time):
 * each position shown, each the record sealed, each pointing at the one
 * before. A position the log holds and the firm did not show is a gap.
 */
export async function checkCompleteness(bundle, ring) {
  const s = await readStatements(bundle?.chain, ring);
  const lines = [...s.lines];
  if (!s.ok) return lines;
  let last = s.length;
  if (bundle.as_of !== undefined) {
    if (!TIME.test(String(bundle.as_of))) return [...lines, { failed: 'as_of is not a time in the form 2026-10-07T12:00:00.000000Z' }];
    last = 0;
    for (let seq = 1; seq <= s.length; seq++) if (s.links.get(seq) && s.links.get(seq).created_at <= bundle.as_of) last = seq;
  }
  for (let seq = 1; seq <= last; seq++) {
    if (!s.links.has(seq)) return [...lines, { failed: `chain: position ${seq} is not in the statements supplied; fetch the page that lists it` }];
  }
  const byDigest = indexRecords(bundle.records, lines);
  let previous = CHAIN_GENESIS;
  let gaps = 0;
  for (let seq = 1; seq <= last; seq++) {
    const link = s.links.get(seq);
    const line = checkPosition(seq, link, s.tag, byDigest, previous);
    if (line.failed) gaps++;
    lines.push(line);
    previous = link.record_digest;
  }
  const extra = [...byDigest.keys()].filter((d) => ![...s.links.values()].some((l) => l.record_digest === d)).length;
  if (extra) lines.push({ skipped: `${extra} record${extra === 1 ? '' : 's'} shown that the statement does not list (later than its head, or in another chain)` });
  lines.push(gaps === 0
    ? { ok: `complete: all ${last} record${last === 1 ? '' : 's'} of the chain ${bundle.as_of ? `sealed by ${bundle.as_of}` : `as of tree size ${s.head.tree_size}`} are shown, in order, none missing` }
    : { failed: `not complete: ${gaps} of ${last} position${last === 1 ? '' : 's'} not shown or not the record sealed` });
  return lines;
}

/** The records a seed selects: each shown, each the record sealed at that position. */
export async function checkSpotCheck(bundle, ring) {
  const s = await readStatements(bundle?.chain, ring);
  const lines = [...s.lines];
  if (!s.ok) return lines;
  let selected;
  try {
    selected = selectSample(bundle.seed, s.length, bundle.sample_size);
  } catch (e) {
    return [...lines, { failed: `spot check: ${e.message}` }];
  }
  lines.push({ ok: `spot check: seed ${bundle.seed.slice(0, 16)}… selects ${selected.length} of ${s.length} positions: ${[...selected].sort((a, b) => a - b).join(', ')}` });
  lines.push({ skipped: `spot check: confirm yourself, on any Bitcoin node or block explorer, that block ${bundle.bitcoin_height ?? '(height not given)'} has hash ${bundle.seed}, and that its height was announced before it was mined` });
  const byDigest = indexRecords(bundle.records, lines);
  let missing = 0;
  for (const seq of selected) {
    const link = s.links.get(seq);
    if (!link) { lines.push({ failed: `position ${seq}: not in the statements supplied; fetch the page that lists it` }); missing++; continue; }
    const before = s.links.get(seq - 1);
    const line = checkPosition(seq, link, s.tag, byDigest, seq === 1 ? CHAIN_GENESIS : before?.record_digest);
    if (line.failed) missing++;
    lines.push(line);
  }
  lines.push(missing === 0 ? { ok: `spot check passed: all ${selected.length} selected records are shown and are the records sealed` }
    : { failed: `spot check failed: ${missing} of ${selected.length} selected records not shown or not the record sealed` });
  return lines;
}

/* -------------------------------------------------------------------- cli */

function opt(args, name) {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
}

async function main() {
  const [mode, ...argv] = process.argv.slice(2);
  const usage = () => {
    console.error('usage: node chains.mjs tag --secret <hex> --name <name> | select --seed <hex> --population <n> --sample <k> | check <file.json> [--key <file|dir>]');
    process.exit(2);
  };
  try {
    if (mode === 'tag') {
      if (!opt(argv, '--secret') || !opt(argv, '--name')) usage();
      console.log(chainTag(opt(argv, '--secret'), opt(argv, '--name')));
    } else if (mode === 'select') {
      const seed = opt(argv, '--seed'); const population = Number(opt(argv, '--population')); const sample = Number(opt(argv, '--sample'));
      if (!seed) usage();
      console.log(JSON.stringify({ seed, population, sample, positions: selectSample(seed, population, sample) }, null, 2));
    } else if (mode === 'check') {
      const file = argv.find((a, i) => !a.startsWith('--') && (i === 0 || !argv[i - 1].startsWith('--')));
      if (!file) usage();
      const { checkArtefacts } = await import('./conformance.mjs');
      const { loadKeyring } = await import('./keyring.mjs');
      const key = opt(argv, '--key');
      const result = await checkArtefacts([file], key ? loadKeyring(key) : null);
      for (const l of result.files[0].lines) console.log(l.ok ? `OK    ${l.ok}` : l.failed ? `FAIL  ${l.failed}` : `SKIP  ${l.skipped}`);
      process.exit(result.conformant ? 0 : 1);
    } else {
      usage();
    }
  } catch (error) {
    console.error(`FAIL  ${error.message}`);
    process.exit(1);
  }
}

if (process.argv[1] && process.argv[1].endsWith('chains.mjs')) main();
