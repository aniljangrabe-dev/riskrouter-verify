#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Anil Jangra
/**
 * The evidence log's signed heads, anchored in Bitcoin, checked offline.
 *
 *   node tools/head-anchor.mjs verify anchors/ots/evidence-head-161.payload.*.ots
 *   node tools/head-anchor.mjs list [--anchors anchors]
 *
 * Owner's request of 18 October 2026: the log's age is the one thing a copy
 * of this software cannot have, so every day's newest signed head goes into a
 * Bitcoin block. What is anchored is the head's frozen payload,
 * riskrouter-evidence-head|v2|tree_size|root_hash|timestamp, as UTF-8 and
 * nothing else, written to anchors/ots/evidence-head-<tree_size>.payload. Its
 * SHA-256 is the digest the OpenTimestamps proofs beside it commit to, and the
 * same imprint the RFC 3161 tokens in anchors/tsa/ carry (docs/legal-time.md),
 * so one head has two kinds of time evidence over one digest. No JSON is
 * hashed, so no formatting can change what was anchored.
 *
 * The standard client checks it with nothing of ours:
 *
 *   ots verify anchors/ots/evidence-head-161.payload.opentimestamps-a.ots anchors/ots/evidence-head-161.payload
 *
 * This file checks what can be checked without a Bitcoin node: the payload is
 * a head payload, the proof commits to its SHA-256, and which state the proof
 * is in (a calendar's promise, or a block). That a block's header really
 * carries the committed root is what `ots verify` adds. Our signature on the
 * head is in the RFC 3161 file for the same size; `list` counts a head only
 * when that signature and its token verify. tests/head-anchor.test.mjs holds
 * this and the Python verifier to the same verdicts.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { otsStatus } from './ots-status.mjs';
import { readTimestamps, verifyTimestampFile } from './tsa.mjs';
import { loadKeyring } from './keyring.mjs';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
export const PAYLOAD_FILE = /^evidence-head-(\d+)\.payload$/;
export const PROOF_FILE = /^(evidence-head-\d+\.payload)\.([a-z0-9-]+)\.ots$/;
const HEAD_PAYLOAD = /^riskrouter-evidence-head\|v2\|(0|[1-9]\d*)\|([0-9a-f]{64})\|(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z)$/;

/* The detached-timestamp header, from the reference implementation (as tools/timestamp.mjs). */
const MAGIC = Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex');
const VERSION = 0x01;
const OP_SHA256 = 0x08;

/** A head payload's fields, or null when the text is not exactly one. */
export function parseHeadPayload(text) {
  const m = HEAD_PAYLOAD.exec(String(text));
  return m ? { tree_size: Number(m[1]), root_hash: m[2], timestamp: m[3] } : null;
}

/** The digest a detached timestamp file starts from, or a reason it has none. */
export function proofDigest(bytes) {
  const b = Buffer.from(bytes);
  if (b.length < MAGIC.length + 2 + 32) return { reason: 'too short to be an OpenTimestamps proof' };
  if (!b.subarray(0, MAGIC.length).equals(MAGIC)) return { reason: 'not an OpenTimestamps proof (header magic)' };
  if (b[MAGIC.length] !== VERSION) return { reason: `unknown proof version ${b[MAGIC.length]}` };
  if (b[MAGIC.length + 1] !== OP_SHA256) return { reason: 'the proof does not start from a SHA-256 digest' };
  return { digest: b.subarray(MAGIC.length + 2, MAGIC.length + 34).toString('hex') };
}

/**
 * One proof against its payload, offline. Lines of { ok | failed | note }, the
 * same verdicts tools/python/riskrouter_verify.py gives for the same files.
 */
export function verifyHeadAnchor(payload, proof, { calendar = 'the calendar' } = {}) {
  const head = parseHeadPayload(Buffer.isBuffer(payload) ? payload.toString('utf8') : payload);
  if (!head) return [{ failed: 'the anchored file is not exactly one evidence-head payload' }];
  const lines = [{ ok: `the anchored file is the head payload for tree size ${head.tree_size}, root ${head.root_hash}, signed for ${head.timestamp}` }];
  const p = proofDigest(proof);
  if (p.reason) return [...lines, { failed: p.reason }];
  const want = crypto.createHash('sha256').update(Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8')).digest('hex');
  if (p.digest !== want) return [...lines, { failed: `the proof commits to ${p.digest}, not to this payload (${want})` }];
  lines.push({ ok: 'the proof commits to the SHA-256 of that payload, the same imprint the RFC 3161 tokens carry' });
  const s = otsStatus(proof);
  if (s.state === 'bitcoin') {
    lines.push({ ok: `the proof carries a Bitcoin attestation: block ${s.blocks.join(', ')}` });
    lines.push({ note: 'that the block header really carries the committed root is what the standard client checks: ots verify <proof> <payload>' });
  } else if (s.state === 'pending') {
    lines.push({ note: `submitted to ${calendar}, not yet in a Bitcoin block; it becomes one after the next upgrade` });
  } else {
    lines.push({ failed: 'the proof carries no attestation at all' });
  }
  return lines;
}

/**
 * Every anchored head, for the site and its figures. A head counts only when
 * our signature on it and an RFC 3161 token verify (its file in anchors/tsa/
 * carries the same payload), so the timeline cannot list a head we never signed.
 */
export function anchoredHeads({ anchorsDir = path.join(ROOT, 'anchors'), ring } = {}) {
  const otsDir = path.join(anchorsDir, 'ots');
  if (!fs.existsSync(otsDir)) return [];
  if (ring === undefined) { try { ring = loadKeyring(anchorsDir); } catch { ring = null; } }
  const stamped = readTimestamps(path.join(anchorsDir, 'tsa')).filter((d) => d.subject === 'riskrouter-evidence-head|v2');
  const files = fs.readdirSync(otsDir);
  return files.filter((f) => PAYLOAD_FILE.test(f))
    .map((f) => {
      const payload = fs.readFileSync(path.join(otsDir, f), 'utf8');
      const head = parseHeadPayload(payload);
      if (!head) return null;
      const tokens = stamped.filter((d) => d.payload === payload && ring && !verifyTimestampFile(d, ring).some((l) => l.failed || l.skipped));
      if (!tokens.length) return null;
      const proofs = files.filter((p) => PROOF_FILE.exec(p)?.[1] === f).sort().map((p) => {
        const bytes = fs.readFileSync(path.join(otsDir, p));
        const bound = !verifyHeadAnchor(payload, bytes).some((l) => l.failed);
        const s = otsStatus(bytes);
        return { calendar: PROOF_FILE.exec(p)[2], file: `anchors/ots/${p}`, state: bound ? s.state : 'unbound', blocks: bound ? s.blocks : [] };
      }).filter((p) => p.state !== 'unbound');
      const blocks = proofs.flatMap((p) => p.blocks);
      return {
        ...head,
        payload_file: `anchors/ots/${f}`,
        tsa: tokens.map((d) => ({ id: d.tsa.id, name: d.tsa.name, gen_time: d.gen_time, qualified: d.tsa.qualified === true })).sort((a, b) => a.id.localeCompare(b.id)),
        proofs,
        block: blocks.length ? Math.min(...blocks) : null
      };
    })
    .filter(Boolean)
    .sort((a, b) => a.tree_size - b.tree_size);
}

/**
 * The head the daily anchor should take: the largest tree size whose RFC 3161
 * file verifies, unless it is already anchored. Throws on an alarm: a payload
 * already anchored for that size that is not the one now held.
 */
export function nextHeadToAnchor({ anchorsDir = path.join(ROOT, 'anchors'), ring } = {}) {
  if (!ring) throw new Error('a keyring is needed: a head is anchored only after our signature on it verifies');
  const good = readTimestamps(path.join(anchorsDir, 'tsa'))
    .filter((d) => d.subject === 'riskrouter-evidence-head|v2' && !verifyTimestampFile(d, ring).some((l) => l.failed || l.skipped))
    .map((d) => ({ head: parseHeadPayload(d.payload), payload: d.payload }))
    .filter((d) => d.head)
    .sort((a, b) => b.head.tree_size - a.head.tree_size);
  if (!good.length) return null;
  const newest = good[0];
  const file = path.join(anchorsDir, 'ots', `evidence-head-${newest.head.tree_size}.payload`);
  if (fs.existsSync(file)) {
    if (fs.readFileSync(file, 'utf8') !== newest.payload) {
      const e = new Error(`ALARM: tree size ${newest.head.tree_size} is anchored with a different payload than the head now held. Two heads for one size is a rewritten history.`);
      e.alarm = true;
      throw e;
    }
    return null;
  }
  return { ...newest, file };
}

/* -------------------------------------------------------------------- cli */

const show = (l) => l.ok ? `OK    ${l.ok}` : l.failed ? `FAIL  ${l.failed}` : `NOTE  ${l.note}`;

function main(argv) {
  const [mode, ...rest] = argv;
  if (mode === 'verify' && rest.length) {
    let failed = false;
    for (const f of rest) {
      const m = PROOF_FILE.exec(path.basename(f));
      console.log(f);
      if (!m) { console.log('  FAIL  not named <evidence-head-N.payload>.<calendar>.ots, so its payload cannot be found'); failed = true; continue; }
      const target = path.join(path.dirname(f), m[1]);
      if (!fs.existsSync(target)) { console.log(`  FAIL  ${target} is missing`); failed = true; continue; }
      for (const l of verifyHeadAnchor(fs.readFileSync(target), fs.readFileSync(f), { calendar: m[2] })) {
        console.log(`  ${show(l)}`);
        failed ||= Boolean(l.failed);
      }
    }
    process.exit(failed ? 1 : 0);
  } else if (mode === 'list') {
    const i = rest.indexOf('--anchors');
    for (const h of anchoredHeads({ anchorsDir: i >= 0 ? rest[i + 1] : undefined })) {
      console.log(`${String(h.tree_size).padStart(7)}  ${h.timestamp}  ${h.block != null ? `block ${h.block}` : h.proofs.length ? 'pending' : 'no proof'}  ${h.tsa.map((t) => t.id).join(',')}`);
    }
  } else {
    console.error('usage: node tools/head-anchor.mjs verify <proof.ots>... | list [--anchors dir]');
    process.exit(2);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) main(process.argv.slice(2));
