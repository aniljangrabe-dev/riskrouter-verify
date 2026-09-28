#!/usr/bin/env node
/**
 * Records for the evidence log: one canonical form, a salted digest, the
 * regime packs that say what to put in a record, and the bundle a firm hands
 * a supervisor. Design and reasoning: docs/regime-packs.md.
 *
 *   node records.mjs packs                                   list the packs and their kinds
 *   node records.mjs validate record.json                    check a record against its pack
 *   node records.mjs digest   record.json [--salt <hex>]     canonical form, salt and record_digest
 *   node records.mjs explain  record.json                    which articles each field is mapped to
 *   node records.mjs bundle   record.json --salt <hex> --proof proof.json   > bundle.json
 *   node records.mjs check    bundle.json [--key <key file or directory>]
 *
 *   --packs <dir>   where the pack files are (default: ./packs beside this file, then ../packs)
 *
 * The canonical form (frozen from the first published vectors):
 *
 *   record         a JSON object; keys ^[a-z][a-z0-9_]{0,63}$ at every level; values are strings
 *                  (valid Unicode), integers within ±(2^53 − 1), true, false, null, arrays and
 *                  objects, nested at most 32 deep. No fractions: money is integer cents.
 *   canonical      RFC 8785 (JSON Canonicalization Scheme) of the record
 *   record_digest  SHA-256(salt || UTF-8(canonical)), salt 16 to 64 random bytes as lowercase hex
 *
 * A pack says, per regime, which fields to record and which article each field
 * is mapped to. It is orientation, not legal advice: the pack links the text on
 * EUR-Lex, and whether an obligation applies or was met stays with the firm.
 *
 * Standard-library Node only, so this file can be copied anywhere and run.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const BUNDLE_FORMAT = 'riskrouter-record-bundle|1';
export const PACK_FORMAT = 'riskrouter-regime-pack|1';
export const RECORD_KEY = /^[a-z][a-z0-9_]{0,63}$/;
export const KIND = /^[a-z0-9][a-z0-9.-]{0,39}$/;          // the log's own kind pattern
export const MAX_DEPTH = 32;
const SALT = /^(?:[0-9a-f]{2}){16,64}$/;
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

export class RecordError extends Error {}

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) &&
  (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);

function serialise(value, depth, where) {
  if (depth > MAX_DEPTH) throw new RecordError(`${where}: nested more than ${MAX_DEPTH} deep`);
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') {
    // RFC 8785 prints numbers as ECMAScript does. Restricting them to safe
    // integers makes that the same digits in every language; -0 prints as 0.
    if (!Number.isSafeInteger(value)) {
      throw new RecordError(`${where}: numbers must be whole and within ±(2^53 − 1); write money as integer cents`);
    }
    return String(value);
  }
  if (typeof value === 'string') {
    if (LONE_SURROGATE.test(value)) throw new RecordError(`${where}: the string is not valid Unicode (a lone surrogate)`);
    return JSON.stringify(value);     // RFC 8785 §3.2.2.2 is exactly this
  }
  if (Array.isArray(value)) return `[${value.map((v, i) => serialise(v, depth + 1, `${where}[${i}]`)).join(',')}]`;
  if (isObject(value)) {
    const keys = Object.keys(value);
    for (const k of keys) {
      if (!RECORD_KEY.test(k)) throw new RecordError(`${where}: key ${JSON.stringify(k)} is not lower-case a-z, 0-9 and _ starting with a letter`);
    }
    // The key alphabet is ASCII, so UTF-16 order (RFC 8785 §3.2.3) is plain byte order.
    keys.sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${serialise(value[k], depth + 1, `${where}.${k}`)}`).join(',')}}`;
  }
  throw new RecordError(`${where}: ${typeof value} is not a JSON value a record may hold`);
}

/** The canonical form of a record, or a RecordError saying why it is not one. */
export function canonicalRecord(record) {
  if (!isObject(record)) throw new RecordError('a record is a JSON object');
  return serialise(record, 1, '$');
}

/** True when the record has a canonical form. */
export function acceptableRecord(record) {
  try { canonicalRecord(record); return true; } catch (e) { if (e instanceof RecordError) return false; throw e; }
}

export function newSalt(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}

/** SHA-256(salt || UTF-8(canonical)), lowercase hex. */
export function recordDigest(saltHex, record) {
  if (typeof saltHex !== 'string' || !SALT.test(saltHex)) {
    throw new RecordError('the salt is 16 to 64 bytes written as lowercase hex (32 to 128 characters)');
  }
  return crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from(saltHex, 'hex'), Buffer.from(canonicalRecord(record), 'utf8')]))
    .digest('hex');
}

/* ------------------------------------------------------------------ packs */

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** Where the pack files are: an explicit directory, else ./packs beside this file, else ../packs. */
export function packsDir(explicit) {
  if (explicit) return explicit;
  for (const candidate of [path.join(HERE, 'packs'), path.join(HERE, '..', 'packs')]) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return path.join(HERE, '..', 'packs');
}

/** Every pack in the directory, by id. */
export function loadPacks(dir = packsDir()) {
  const packs = new Map();
  if (!fs.existsSync(dir)) return packs;
  for (const f of fs.readdirSync(dir).filter((n) => n.endsWith('.json')).sort()) {
    const pack = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
    if (pack.format !== PACK_FORMAT) continue;
    packs.set(pack.id, pack);
  }
  return packs;
}

// Every record carries these; a pack's kinds add their own fields.
export const COMMON_FIELDS = [
  { name: 'pack', type: 'string', required: true, description: 'The pack id.' },
  { name: 'pack_version', type: 'integer', required: true, description: 'The pack version.' },
  { name: 'kind', type: 'string', required: true, description: 'The kind; the same tag sent to the log.' },
  { name: 'record_id', type: 'reference', required: true, description: 'Your own id for this record.' },
  { name: 'supersedes', type: 'reference', required: false, description: 'The record_id of an earlier record this one corrects. The earlier record stays.' }
];

const REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const TEXT_MAX = 20000;
export const FIELD_TYPES = ['reference', 'text', 'string', 'enum', 'integer', 'boolean', 'date', 'timestamp', 'digest', 'list'];

function realDate(s) {
  const [y, m, d] = s.slice(0, 10).split('-').map(Number);
  const t = new Date(Date.UTC(y, m - 1, d));
  return t.getUTCFullYear() === y && t.getUTCMonth() === m - 1 && t.getUTCDate() === d;
}

/** Why a value does not fit a field, or null when it does. */
export function fieldProblem(field, value) {
  switch (field.type) {
    case 'reference':
      // Your own ids. The alphabet has no space and no @, so a name or an email is refused here.
      return typeof value === 'string' && REFERENCE.test(value) ? null
        : 'must be your own reference: letters, digits and . _ : / - only, at most 128, no names or emails';
    case 'text':
      return typeof value === 'string' && value.length > 0 && value.length <= (field.max_length || TEXT_MAX) ? null
        : `must be text, 1 to ${field.max_length || TEXT_MAX} characters`;
    case 'string':
      return typeof value === 'string' && value.length > 0 && value.length <= (field.max_length || 200) && !/[\u0000-\u001f]/.test(value) ? null
        : `must be a single line of 1 to ${field.max_length || 200} characters`;
    case 'enum':
      return field.values.includes(value) ? null : `must be one of ${field.values.join(', ')}`;
    case 'integer':
      return Number.isSafeInteger(value) && (field.min === undefined || value >= field.min) && (field.max === undefined || value <= field.max) ? null
        : `must be a whole number${field.min !== undefined ? ` of at least ${field.min}` : ''}`;
    case 'boolean':
      return typeof value === 'boolean' ? null : 'must be true or false';
    case 'date':
      return typeof value === 'string' && DATE.test(value) && realDate(value) ? null : 'must be a date, YYYY-MM-DD';
    case 'timestamp':
      return typeof value === 'string' && TIMESTAMP.test(value) && realDate(value) ? null : 'must be a UTC time, YYYY-MM-DDTHH:MM:SS[.ffffff]Z';
    case 'digest':
      return typeof value === 'string' && DIGEST.test(value) ? null : 'must be a lowercase hex SHA-256';
    case 'list': {
      if (!Array.isArray(value) || value.length === 0) return 'must be a non-empty list';
      for (const [i, item] of value.entries()) {
        const p = fieldProblem(field.items, item);
        if (p) return `item ${i} ${p}`;
      }
      return null;
    }
    default:
      return `has an unknown type ${field.type}`;
  }
}

/**
 * A record against its pack: the common fields, the kind's own fields,
 * nothing else except x_ extensions. Returns { ok, errors, pack, kind }.
 */
export function validateRecord(record, packs = loadPacks()) {
  const errors = [];
  try { canonicalRecord(record); } catch (e) { return { ok: false, errors: [e.message] }; }
  const pack = packs.get(record.pack);
  if (!pack) return { ok: false, errors: [`no pack ${JSON.stringify(record.pack)}; known: ${[...packs.keys()].join(', ') || 'none'}`] };
  if (record.pack_version !== pack.version) errors.push(`pack_version is ${JSON.stringify(record.pack_version)}, this pack is version ${pack.version}`);
  const kind = pack.kinds.find((k) => k.kind === record.kind);
  if (!kind) return { ok: false, errors: [...errors, `pack ${pack.id} has no kind ${JSON.stringify(record.kind)}; its kinds: ${pack.kinds.map((k) => k.kind).join(', ')}`], pack };
  const fields = [...COMMON_FIELDS, ...kind.fields];
  for (const f of fields) {
    if (!(f.name in record)) { if (f.required) errors.push(`${f.name} is required`); continue; }
    if (['pack', 'pack_version', 'kind'].includes(f.name)) continue;
    const p = fieldProblem(f, record[f.name]);
    if (p) errors.push(`${f.name} ${p}`);
  }
  const known = new Set(fields.map((f) => f.name));
  for (const k of Object.keys(record)) {
    if (!known.has(k) && !k.startsWith('x_')) errors.push(`${k} is not a field of ${kind.kind}; your own fields start with x_`);
  }
  return { ok: errors.length === 0, errors, pack, kind };
}

/** For each field present in the record, the articles its pack maps it to. */
export function explainRecord(record, packs = loadPacks()) {
  const pack = packs.get(record.pack);
  const kind = pack?.kinds.find((k) => k.kind === record.kind);
  if (!kind) return null;
  const articles = new Map(pack.articles.map((a) => [a.id, a]));
  const instruments = new Map(pack.instruments.map((i) => [i.id, i]));
  const covered = new Map();
  for (const f of kind.fields) {
    if (!(f.name in record)) continue;
    for (const id of f.evidences || []) {
      if (!covered.has(id)) covered.set(id, []);
      covered.get(id).push(f.name);
    }
  }
  return {
    pack: pack.id, kind: kind.kind, title: kind.title,
    articles: [...covered.entries()].map(([id, fieldsHere]) => {
      const a = articles.get(id);
      const inst = instruments.get(a.instrument);
      return { id, ref: `${inst.name}, ${a.ref}`, source: inst.source, fields: fieldsHere };
    })
  };
}

/* ---------------------------------------------------------------- bundles */

/** What a firm hands a supervisor: the record, its salt, and the log's proof for its digest. */
export function makeBundle(record, saltHex, proof) {
  return { format: BUNDLE_FORMAT, record, salt_hex: saltHex, proof };
}

/**
 * The record half of a bundle: the canonical form exists, the digest recomputes
 * to the entry's record_digest, and the record's kind is the entry's kind. The
 * proof half (leaf, audit path, head, signatures) is checked by the verifiers,
 * as for any evidence proof. Returns lines of { ok | failed | skipped }.
 */
export function checkBundleRecord(bundle, packs = loadPacks()) {
  const lines = [];
  const entry = bundle?.proof?.entry || {};
  let digest;
  try {
    digest = recordDigest(bundle.salt_hex, bundle.record);
  } catch (e) {
    lines.push({ failed: `record: ${e.message}` });
    return lines;
  }
  lines.push(digest === entry.record_digest
    ? { ok: `record: the record and its salt produce the recorded digest ${digest.slice(0, 16)}…` }
    : { failed: 'record: the record and its salt do not produce the digest in the proof; the record is not the one recorded' });
  if (bundle.record.kind !== undefined || entry.kind !== undefined) {
    lines.push(bundle.record.kind === entry.kind
      ? { ok: `record: its kind ${entry.kind} is the kind recorded` }
      : { failed: `record: its kind ${JSON.stringify(bundle.record.kind)} is not the kind recorded, ${JSON.stringify(entry.kind)}` });
  }
  if (bundle.record.pack !== undefined) {
    const v = validateRecord(bundle.record, packs);
    lines.push(v.ok ? { ok: `record: fits pack ${v.pack.id} v${v.pack.version}, kind ${v.kind.kind}` }
      : v.pack ? { failed: `record: does not fit pack ${v.pack.id}: ${v.errors.join('; ')}` }
        : { skipped: `record: ${v.errors[0]}` });
  }
  return lines;
}

/* -------------------------------------------------------------------- cli */

function opt(args, name) {
  const i = args.indexOf(name);
  if (i === -1) return { value: undefined, rest: args };
  return { value: args[i + 1], rest: [...args.slice(0, i), ...args.slice(i + 2)] };
}

// Run as a function, not with top-level await: `check` imports conformance.mjs,
// which imports this module, and a module still awaiting at top level would
// never finish evaluating for that import to complete.
async function main() {
  const [mode, ...argv] = process.argv.slice(2);
  const packsOpt = opt(argv, '--packs'); const saltOpt = opt(packsOpt.rest, '--salt');
  const proofOpt = opt(saltOpt.rest, '--proof'); const keyOpt = opt(proofOpt.rest, '--key');
  const [file] = keyOpt.rest;
  const packs = loadPacks(packsDir(packsOpt.value));
  const read = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
  const out = (doc) => process.stdout.write(JSON.stringify(doc, null, 2) + '\n');
  const usage = () => {
    console.error('usage: node records.mjs packs | validate <record.json> | digest <record.json> [--salt hex] | explain <record.json>\n' +
      '                       | bundle <record.json> --salt <hex> --proof <proof.json> | check <bundle.json> [--key <file|dir>]   [--packs <dir>]');
    process.exit(2);
  };
  try {
    if (mode === 'packs') {
      for (const p of packs.values()) {
        console.log(`${p.id} v${p.version}  ${p.title}`);
        for (const k of p.kinds) console.log(`  ${k.kind.padEnd(30)} ${k.title}`);
      }
    } else if (mode === 'validate') {
      if (!file) usage();
      const v = validateRecord(read(file), packs);
      console.log(v.ok ? `OK    fits pack ${v.pack.id} v${v.pack.version}, kind ${v.kind.kind}` : v.errors.map((e) => `FAIL  ${e}`).join('\n'));
      process.exit(v.ok ? 0 : 1);
    } else if (mode === 'digest') {
      if (!file) usage();
      const record = read(file);
      const salt = saltOpt.value || newSalt();
      out({ kind: record.kind ?? null, salt_hex: salt, record_digest: recordDigest(salt, record), canonical: canonicalRecord(record),
        keep: 'Keep the record and the salt. Send only record_digest and kind to POST /api/v2/evidence.' });
    } else if (mode === 'explain') {
      if (!file) usage();
      const e = explainRecord(read(file), packs);
      if (!e) { console.log('FAIL  the record names no pack and kind this directory knows'); process.exit(1); }
      console.log(`${e.pack} / ${e.kind}: ${e.title}`);
      for (const a of e.articles) console.log(`  ${a.ref}\n      mapped from: ${a.fields.join(', ')}\n      text: ${a.source}`);
      console.log('Orientation, not legal advice: whether an obligation applies or was met is yours and your supervisor\'s to decide.');
    } else if (mode === 'bundle') {
      if (!file || !saltOpt.value || !proofOpt.value) usage();
      const bundle = makeBundle(read(file), saltOpt.value, read(proofOpt.value));
      const lines = checkBundleRecord(bundle, packs);
      for (const l of lines) console.error(l.ok ? `OK    ${l.ok}` : l.failed ? `FAIL  ${l.failed}` : `SKIP  ${l.skipped}`);
      if (lines.some((l) => l.failed)) process.exit(1);
      out(bundle);
    } else if (mode === 'check') {
      if (!file) usage();
      const { checkArtefacts } = await import('./conformance.mjs');
      const { loadKeyring } = await import('./keyring.mjs');
      const result = await checkArtefacts([file], keyOpt.value ? loadKeyring(keyOpt.value) : null);
      for (const l of result.files[0].lines) console.log(l.ok ? `OK    ${l.ok}` : l.failed ? `FAIL  ${l.failed}` : `SKIP  ${l.skipped}`);
      const e = explainRecord(read(file).record || {}, packs);
      if (e && !result.failed) {
        console.log(`\nThe record's fields are mapped by pack ${e.pack} to:`);
        for (const a of e.articles) console.log(`  ${a.ref}  (${a.fields.join(', ')})`);
        console.log('Orientation, not legal advice: whether an obligation applies or was met is yours and your supervisor\'s to decide.');
      }
      process.exit(result.conformant ? 0 : 1);
    } else {
      usage();
    }
  } catch (error) {
    console.error(`FAIL  ${error.message}`);
    process.exit(1);
  }
}

if (process.argv[1] && process.argv[1].endsWith('records.mjs')) main();
