#!/usr/bin/env node
/**
 * The conformance suite: does an implementation of the RiskRouter evidence
 * formats produce the same bytes the specification does?
 *
 *   node conformance.mjs cases                                   > cases.json
 *   node conformance.mjs grade  answers.json [--name "Brio 12.4"] > result.json
 *   node conformance.mjs run    --command "python3 my_impl.py" [--name ...] > result.json
 *   node conformance.mjs artefacts <file|directory>... [--key <key file or directory>] > result.json
 *   node conformance.mjs self                                    > result.json
 *
 * Every case is derived from spec-vectors.json, the same deterministic vectors
 * /spec publishes, plus a few deliberately broken proofs that must be refused.
 * An implementation in any language answers the cases (`cases` writes them,
 * the implementation writes `answers`, `grade` compares; or `run` drives a
 * command that reads one case on stdin and prints its answer) and gets back a
 * result file it can publish. `artefacts` checks what an implementation
 * produced — an export, a single-entry proof, an evidence proof, a broker-desk
 * evidence pack, a record bundle, an RFC 3161 head timestamp — with the verifiers a regulator would use. `self` runs this
 * repository's own reference code through the same cases, which is how the
 * suite is tested against the code that defines the formats.
 *
 * What a result says, exactly: this implementation, on this date, answered
 * these cases as the specification's vectors say. It is the implementer's own
 * statement about their software. RiskRouter certifies nothing and nobody;
 * the result file names the vector set it was graded against so anyone can
 * re-run it.
 *
 * Standard-library Node. Imports only the reference verifiers beside it.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalForm, verifyExport, verifyEntryProof } from './verify-ledger.mjs';
import { leafHash, leafString, rootHash, headPayload, canonicalTimestamp, verifyInclusion, verifyConsistency, claimPayload, verifyClaim } from './merkle.mjs';
import { loadKeyring, pickKey } from './keyring.mjs';
import { canonicalRecord, recordDigest, acceptableRecord, checkBundleRecord, BUNDLE_FORMAT } from './records.mjs';
import { verifyTimestampFile, TIMESTAMP_FORMAT } from './tsa.mjs';

export const RESULT_FORMAT = 'riskrouter-conformance-result|1';
export const ANSWERS_FORMAT = 'riskrouter-conformance-answers|1';
export const CASES_FORMAT = 'riskrouter-conformance-cases|1';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const enc = (s) => new TextEncoder().encode(s);
const flipHex = (h) => h.slice(0, -1) + (h.at(-1) === '0' ? '1' : '0');

/** The vectors: beside this file (the published kit) or one level up (this repository). */
export function loadVectors(explicit) {
  const candidates = explicit ? [explicit] : [path.join(HERE, 'spec-vectors.json'), path.join(HERE, '..', 'spec-vectors.json')];
  const found = candidates.find((f) => fs.existsSync(f));
  if (!found) throw new Error(`spec-vectors.json not found (looked in ${candidates.join(', ')}); pass --vectors <file>`);
  return JSON.parse(fs.readFileSync(found, 'utf8'));
}

/* ---------------------------------------------------------------- cases */

/**
 * Every case has an operation, an input and the answer the specification
 * expects. The broken proofs are built from the good ones by changing one
 * thing, so an implementation that verifies everything passes the good cases
 * and fails these; that is the point of them.
 */
export function buildCases(v) {
  const cases = [];
  const add = (op, input, expect) => cases.push({ id: `${op}#${String(cases.filter((c) => c.op === op).length + 1).padStart(2, '0')}`, op, input, expect });

  for (const t of v.timestamps) add('timestamp.canonical', { value: t.input }, t.canonical);

  add('v1.canonical_form', { row: v.v1_entry.row, prev_hash: v.v1_entry.prev_hash }, v.v1_entry.canonical_form);
  add('v1.row_hash', { row: v.v1_entry.row, prev_hash: v.v1_entry.prev_hash }, v.v1_entry.row_hash);
  add('v1.attestation_payload', { attestation: v.v1_attestation_payload.attestation }, v.v1_attestation_payload.payload);

  for (const e of v.v2_entries) add('v2.leaf_string', { entry: e.entry }, e.leaf_string);
  for (const e of v.v2_entries) add('v2.leaf_hash', { entry: e.entry }, e.leaf_hash);
  const leaves = v.v2_entries.map((e) => e.leaf_hash);
  for (const t of v.v2_roots) add('v2.root_hash', { leaf_hashes: leaves.slice(0, t.tree_size) }, t.root_hash);
  add('v2.root_hash', { leaf_hashes: [] }, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

  const inc = v.v2_inclusion;
  const incInput = { leaf_index: inc.leaf_index, tree_size: inc.tree_size, leaf_hash: inc.leaf_hash, audit_path: inc.audit_path, root_hash: inc.root_hash };
  add('v2.inclusion', incInput, true);
  add('v2.inclusion', { ...incInput, root_hash: flipHex(inc.root_hash) }, false);
  add('v2.inclusion', { ...incInput, leaf_hash: flipHex(inc.leaf_hash) }, false);
  add('v2.inclusion', { ...incInput, leaf_index: inc.leaf_index === 0 ? 1 : inc.leaf_index - 1 }, false);
  add('v2.inclusion', { ...incInput, audit_path: inc.audit_path.slice(0, -1) }, false);
  add('v2.inclusion', { ...incInput, audit_path: [...inc.audit_path, inc.audit_path[0]] }, false);

  const con = v.v2_consistency;
  const conInput = { first: con.first, second: con.second, first_root: con.first_root, second_root: con.second_root, proof: con.proof };
  add('v2.consistency', conInput, true);
  add('v2.consistency', { ...conInput, first_root: flipHex(con.first_root) }, false);
  add('v2.consistency', { ...conInput, second_root: flipHex(con.second_root) }, false);
  add('v2.consistency', { ...conInput, proof: con.proof.slice(0, -1) }, false);
  add('v2.consistency', { ...conInput, first: con.first + 1 }, false);

  add('v2.head_payload', { head: v.v2_head.head }, v.v2_head.payload);
  if (v.v3_entry) {
    add('v3.leaf_string', { entry: v.v3_entry.entry }, v.v3_entry.leaf_string);
    add('v3.leaf_hash', { entry: v.v3_entry.entry }, v.v3_entry.leaf_hash);
    add('v3.claim_payload', { entry: v.v3_claim.entry }, v.v3_claim.payload);
  }
  // Records (docs/regime-packs.md): the canonical form and the salted digest,
  // and records an implementation must refuse to canonicalise.
  for (const r of v.records || []) {
    add('record.canonical', { record: r.record }, r.canonical);
    add('record.digest', { salt_hex: r.salt_hex, record: r.record }, r.record_digest);
    add('record.acceptable', { record: r.record }, true);
  }
  for (const r of v.records_refused || []) add('record.acceptable', { record: r.record }, false);
  const cs = v.v2_cosignature;
  add('v2.cosign_payload', { witness_id: cs.witness_id, tree_size: cs.tree_size, root_hash: cs.root_hash, cosigned_at: cs.cosigned_at }, cs.payload);

  return { format: CASES_FORMAT, vectors: v.format, cases_digest: sha(JSON.stringify(cases)), cases };
}

/* ------------------------------------------------------- the reference */

/** This repository's own code answering a case; `self` and the tests use it. */
export async function referenceAnswer(c) {
  const i = c.input;
  switch (c.op) {
    case 'timestamp.canonical': return canonicalTimestamp(i.value);
    case 'v1.canonical_form': return canonicalForm(i.row, i.prev_hash);
    case 'v1.row_hash': return sha(canonicalForm(i.row, i.prev_hash));
    case 'v1.attestation_payload': return attestationPayload(i.attestation);
    case 'v2.leaf_string': return leafString(i.entry);
    case 'v2.leaf_hash': return leafHash(enc(leafString(i.entry)));
    case 'v2.root_hash': return rootHash(i.leaf_hashes);
    case 'v2.inclusion': return verifyInclusion(i.leaf_index, i.tree_size, i.leaf_hash, i.audit_path, i.root_hash);
    case 'v2.consistency': return verifyConsistency(i.first, i.second, i.first_root, i.second_root, i.proof);
    case 'v2.head_payload': return headPayload(i.head);
    case 'v3.leaf_string': return leafString(i.entry);
    case 'v3.leaf_hash': return leafHash(enc(leafString(i.entry)));
    case 'v3.claim_payload': return claimPayload(i.entry);
    case 'record.canonical': return canonicalRecord(i.record);
    case 'record.digest': return recordDigest(i.salt_hex, i.record);
    case 'record.acceptable': return acceptableRecord(i.record);
    case 'v2.cosign_payload': return ['riskrouter-evidence-cosign', 'v2', i.witness_id, String(i.tree_size), i.root_hash, i.cosigned_at].join('|');
    default: throw new Error(`unknown operation ${c.op}`);
  }
}

function attestationPayload(a) {
  return ['riskrouter-ledger-attestation', 'v1', String(a.as_of ?? ''), String(a.entries ?? ''), String(a.head_hash ?? '')].join('|');
}

/* ---------------------------------------------------------------- grade */

const same = (expect, got) => typeof expect === 'boolean' ? got === expect : typeof got === 'string' && got === expect;

/**
 * Compare answers with the cases. `answers` is the implementation's file:
 * { format, implementation: {name, version}, cases_digest, answers: {id: value} },
 * or simply {id: value}. An answer that is missing is a failure, not a skip:
 * a suite an implementation can pass by leaving cases out proves nothing.
 */
export function grade(casesDoc, answersDoc, implementation = {}) {
  const answers = answersDoc && typeof answersDoc === 'object' && answersDoc.answers && typeof answersDoc.answers === 'object'
    ? answersDoc.answers : answersDoc || {};
  const failed = [];
  for (const c of casesDoc.cases) {
    const got = answers[c.id];
    if (!same(c.expect, got)) failed.push({ id: c.id, op: c.op, expected: c.expect, got: got === undefined ? null : got });
  }
  const notes = [];
  if (answersDoc?.cases_digest && answersDoc.cases_digest !== casesDoc.cases_digest) {
    notes.push(`the answers were made for cases ${answersDoc.cases_digest.slice(0, 16)}…, not these (${casesDoc.cases_digest.slice(0, 16)}…)`);
  }
  const named = { ...(answersDoc?.implementation || {}), ...implementation };
  return {
    format: RESULT_FORMAT,
    vectors: casesDoc.vectors,
    cases_digest: casesDoc.cases_digest,
    implementation: { name: named.name || 'unnamed', version: named.version || null, language: named.language || null },
    graded_at: new Date().toISOString(),
    cases: casesDoc.cases.length,
    passed: casesDoc.cases.length - failed.length,
    failed,
    notes,
    conformant: failed.length === 0 && notes.length === 0,
    statement: failed.length === 0 && notes.length === 0
      ? `${named.name || 'This implementation'} answered all ${casesDoc.cases.length} cases of the RiskRouter evidence conformance suite (${casesDoc.vectors}) as the specification expects.`
      : `${named.name || 'This implementation'} does not conform: ${failed.length} of ${casesDoc.cases.length} cases differ from the specification.`
  };
}

/** Drive a command per case: the case as JSON on stdin, its answer on stdout. */
export function runCommand(casesDoc, command, { timeout = 20000 } = {}) {
  const answers = {};
  for (const c of casesDoc.cases) {
    const r = spawnSync(command, { shell: true, input: JSON.stringify(c), encoding: 'utf8', timeout });
    const out = (r.stdout || '').trim();
    let value;
    try {
      const parsed = JSON.parse(out);
      value = parsed && typeof parsed === 'object' && !Array.isArray(parsed) && 'output' in parsed ? parsed.output : parsed;
    } catch {
      value = out === 'true' ? true : out === 'false' ? false : out;
    }
    if (r.status !== 0 && value === '') value = `(exit ${r.status}${r.stderr ? ': ' + r.stderr.trim().slice(0, 200) : ''})`;
    answers[c.id] = value;
  }
  return { format: ANSWERS_FORMAT, cases_digest: casesDoc.cases_digest, answers };
}

/* ------------------------------------------------------------ artefacts */

function verifyP256(published, payload, signatureB64) {
  try {
    const key = crypto.createPublicKey({ key: published.public_key, format: 'jwk' });
    return crypto.verify('sha256', Buffer.from(payload, 'utf8'), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(String(signatureB64), 'base64'));
  } catch {
    return false;
  }
}

function checkSignature(ring, payload, signature, what) {
  if (!ring) return { skipped: `${what}: no key supplied (--key), signature not checked` };
  if (!signature) return { failed: `${what}: carries no signature` };
  if (signature.signed_payload && signature.signed_payload !== payload) return { failed: `${what}: the signature covers different content than the file claims` };
  const published = pickKey(ring, signature.key_id);
  if (!published) return { failed: `${what}: signed with key ${signature.key_id || '(unnamed)'}, which is not among the keys supplied` };
  return verifyP256(published, payload, signature.signature) ? { ok: `${what}: signature verifies (key ${published.key_id || '(unnamed)'})` }
    : { failed: `${what}: the signature does not verify against the key supplied` };
}

async function verifyEvidenceProof(doc, savedHead) {
  const entry = doc.entry || {};
  let leaf;
  try { leaf = await leafHash(enc(leafString(entry))); } catch { return { intact: false, reason: 'the proof carries no complete entry' }; }
  if (entry.leaf_hash && entry.leaf_hash !== leaf) return { intact: false, reason: 'the entry does not produce the leaf hash it claims' };
  const head = savedHead || doc.head;
  if (!head) return { intact: false, reason: 'no head to check against' };
  if (Number(head.tree_size) !== Number(doc.tree_size)) return { intact: false, reason: `the proof is for tree_size ${doc.tree_size} but the head is for ${head.tree_size}` };
  const ok = await verifyInclusion(Number(entry.leaf_index), Number(head.tree_size), leaf, doc.audit_path || [], head.root_hash);
  if (!ok) return { intact: false, reason: 'the audit path does not lead from this entry to the head\'s root' };
  if (Number(entry.leaf_version) === 3) {
    // A signed leaf: the decision-maker's own signature is part of what "intact" means.
    if (!doc.signer_public_key) return { intact: false, reason: 'a v3 leaf, but the proof carries no signer_public_key' };
    if (!(await verifyClaim(entry, doc.signer_public_key))) return { intact: false, reason: 'the client signature does not verify over the claim payload with the signer\'s key' };
  }
  return { intact: true, leaf_index: Number(entry.leaf_index), tree_size: Number(head.tree_size), signed_by: entry.signer_key_id };
}

/** One artefact, by the format it declares (a pack declares none, so by shape). */
export async function checkArtefact(doc, ring) {
  const lines = [];
  const push = (r) => { lines.push(r); return r; };
  const fmt = typeof doc?.format === 'string' ? doc.format : '';
  if (fmt.startsWith('riskrouter-ledger-export|')) {
    const r = verifyExport(doc);
    push(r.intact ? { ok: `export: ${r.entries ?? ''} entries chain to head ${String(r.head || '').slice(0, 16)}…`.replace('  ', ' ') } : { failed: `export: ${r.reason}` });
    push(checkSignature(ring, attestationPayload(doc.attestation || {}), doc.signature, 'export attestation'));
  } else if (fmt === 'riskrouter-entry-proof|v1') {
    const r = verifyEntryProof(doc);
    push(r.intact ? { ok: `entry proof: entry ${r.index} links to the head` } : { failed: `entry proof: ${r.reason}` });
    push(checkSignature(ring, attestationPayload(doc.attestation || {}), doc.signature, 'entry proof attestation'));
  } else if (fmt === 'riskrouter-evidence-proof|v2') {
    const r = await verifyEvidenceProof(doc);
    push(r.intact ? { ok: `evidence proof: entry ${r.leaf_index} is in the tree of size ${r.tree_size}${r.signed_by ? `, signed by ${r.signed_by}` : ''}` } : { failed: `evidence proof: ${r.reason}` });
    push(doc.head ? checkSignature(ring, headPayload(doc.head), doc.signature, 'evidence head') : { failed: 'evidence proof: carries no head' });
  } else if (fmt === TIMESTAMP_FORMAT) {
    // An RFC 3161 token on one of our heads (docs/legal-time.md). Notes are information, not checks.
    for (const l of verifyTimestampFile(doc, ring)) if (!l.note) push(l);
  } else if (fmt === BUNDLE_FORMAT) {
    // A record bundle: the record half, then the proof exactly as any evidence proof.
    for (const l of checkBundleRecord(doc)) push(l);
    const r = await verifyEvidenceProof(doc.proof || {});
    push(r.intact ? { ok: `evidence proof: entry ${r.leaf_index} is in the tree of size ${r.tree_size}${r.signed_by ? `, signed by ${r.signed_by}` : ''}` } : { failed: `evidence proof: ${r.reason}` });
    push(doc.proof?.head ? checkSignature(ring, headPayload(doc.proof.head), doc.proof.signature, 'evidence head') : { failed: 'evidence proof: carries no head' });
  } else if (doc?.demands_and_needs && doc?.evidence_proof && doc?.quote_proof) {
    const dn = doc.demands_and_needs;
    let digest = null;
    try { digest = crypto.createHash('sha256').update(Buffer.concat([Buffer.from(dn.salt_hex, 'hex'), Buffer.from(dn.note, 'utf8')])).digest('hex'); } catch { /* reported below */ }
    push(digest && digest === doc.evidence_proof?.entry?.record_digest ? { ok: 'pack: the note and its salt produce the recorded digest' } : { failed: 'pack: the note and its salt do not produce the recorded digest' });
    for (const r of (await checkArtefact(doc.evidence_proof, ring))) push(r);
    for (const r of (await checkArtefact(doc.quote_proof, ring))) push(r);
  } else if (fmt === 'riskrouter-evidence-cosignature|v2' || fmt === 'riskrouter-evidence-consistency|v2') {
    push({ skipped: `${fmt}: needs the head or witness key the holder saved; check it with riskrouter_verify.py` });
  } else {
    push({ failed: `not a RiskRouter artefact this suite knows (format ${JSON.stringify(doc?.format ?? null)})` });
  }
  return lines;
}

export async function checkArtefacts(files, ring, implementation = {}) {
  const results = [];
  for (const file of files) {
    let doc;
    try { doc = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { results.push({ file, lines: [{ failed: `not JSON: ${e.message}` }] }); continue; }
    results.push({ file, lines: await checkArtefact(doc, ring) });
  }
  const all = results.flatMap((r) => r.lines);
  const failed = all.filter((l) => l.failed).length;
  const skipped = all.filter((l) => l.skipped).length;
  return {
    format: RESULT_FORMAT,
    mode: 'artefacts',
    implementation: { name: implementation.name || 'unnamed', version: implementation.version || null },
    graded_at: new Date().toISOString(),
    files: results,
    checks: all.length,
    passed: all.filter((l) => l.ok).length,
    failed,
    skipped,
    conformant: failed === 0 && all.length > 0,
    statement: failed === 0 && all.length > 0
      ? `Every artefact checked verifies with the reference verifiers${skipped ? ` (${skipped} signature check${skipped === 1 ? '' : 's'} skipped: no key supplied)` : ''}.`
      : 'At least one artefact does not verify.'
  };
}

/* ------------------------------------------------------------------ cli */

function expandFiles(args) {
  return args.flatMap((a) => fs.statSync(a).isDirectory()
    ? fs.readdirSync(a).filter((f) => f.endsWith('.json')).sort().map((f) => path.join(a, f)) : [a]);
}

function opt(args, name) {
  const i = args.indexOf(name);
  if (i === -1) return { value: undefined, rest: args };
  return { value: args[i + 1], rest: [...args.slice(0, i), ...args.slice(i + 2)] };
}

if (process.argv[1] && process.argv[1].endsWith('conformance.mjs')) {
  const [mode, ...argv] = process.argv.slice(2);
  const name = opt(argv, '--name'); const version = opt(name.rest, '--version'); const vectorsOpt = opt(version.rest, '--vectors');
  const command = opt(vectorsOpt.rest, '--command'); const keyOpt = opt(command.rest, '--key');
  const rest = keyOpt.rest;
  const implementation = Object.fromEntries(Object.entries({ name: name.value, version: version.value }).filter(([, v]) => v !== undefined));
  const out = (doc) => process.stdout.write(JSON.stringify(doc, null, 2) + '\n');
  const usage = () => {
    console.error('usage: node conformance.mjs cases | grade <answers.json> | run --command "<cmd>" | artefacts <file|dir>... [--key <file|dir>] | self   [--name <impl> --version <v>]');
    process.exit(2);
  };
  try {
    if (mode === 'cases') {
      out(buildCases(loadVectors(vectorsOpt.value)));
    } else if (mode === 'grade') {
      if (!rest[0]) usage();
      const result = grade(buildCases(loadVectors(vectorsOpt.value)), JSON.parse(fs.readFileSync(rest[0], 'utf8')), implementation);
      out(result); process.exit(result.conformant ? 0 : 1);
    } else if (mode === 'run') {
      if (!command.value) usage();
      const cases = buildCases(loadVectors(vectorsOpt.value));
      const result = grade(cases, runCommand(cases, command.value), implementation);
      out(result); process.exit(result.conformant ? 0 : 1);
    } else if (mode === 'self') {
      const cases = buildCases(loadVectors(vectorsOpt.value));
      const answers = {};
      for (const c of cases.cases) answers[c.id] = await referenceAnswer(c);
      const result = grade(cases, { format: ANSWERS_FORMAT, cases_digest: cases.cases_digest, answers }, { name: 'RiskRouter reference (tools/)', ...implementation });
      out(result); process.exit(result.conformant ? 0 : 1);
    } else if (mode === 'artefacts') {
      if (!rest.length) usage();
      const ring = keyOpt.value ? loadKeyring(keyOpt.value) : null;
      const result = await checkArtefacts(expandFiles(rest), ring, implementation);
      out(result); process.exit(result.conformant ? 0 : 1);
    } else {
      usage();
    }
  } catch (error) {
    console.error(`FAIL  ${error.message}`);
    process.exit(1);
  }
}
