#!/usr/bin/env node
/**
 * Check a ledger against every head hash we have ever published.
 *
 * A chain proves history was not edited. It cannot prove history was not
 * rebuilt, because a rebuild recomputes every digest consistently and looks
 * perfect. The only defence is an earlier head recorded somewhere we cannot
 * reach — which is what anchors/ is for.
 *
 * Until this script existed, that directory was a pile of files nobody
 * compared to anything. An anchor you never check is a receipt in a drawer.
 * This is the check:
 *
 *   for each anchored attestation (entries = N, head = H)
 *     the ledger's head after its first N entries must still be H
 *
 * One mismatch means the ledger was rebuilt after that anchor was taken. There
 * is no innocent explanation and no version of it we get to talk our way out
 * of, which is the entire reason the anchors are signed and published.
 *
 *   node tools/verify-anchors.mjs export.json
 *   node tools/verify-anchors.mjs rows.json --anchors anchors
 *   node tools/verify-anchors.mjs export.json --skip-signatures
 *
 * Signatures are checked by spawning tools/verify-attestation.mjs — the same
 * tool a holder would run — rather than reimplementing the check here. Two
 * copies of a signature verifier is two chances to get it subtly wrong.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalForm } from './verify-ledger.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GENESIS = '0'.repeat(64);

/** Head hash after each prefix: heads[n] is the head once n entries exist. */
export function headsByCount(doc) {
  const heads = new Map([[0, GENESIS]]);

  if (doc && Array.isArray(doc.skeleton) && doc.skeleton.length) {
    // An export already carries the published digests; take them as given.
    const ordered = [...doc.skeleton].sort((a, b) => Number(a.chain_index) - Number(b.chain_index));
    for (const link of ordered) heads.set(Number(link.chain_index), link.row_hash);
    return heads;
  }

  // Raw rows: rebuild every digest from content, which is stronger.
  const rows = Array.isArray(doc) ? doc : (doc.rows || doc.entries || []);
  const ordered = [...rows].sort((a, b) => Number(a.chain_index) - Number(b.chain_index));
  let prev = GENESIS;
  for (const row of ordered) {
    prev = crypto.createHash('sha256').update(canonicalForm(row, prev)).digest('hex');
    heads.set(Number(row.chain_index), prev);
  }
  return heads;
}

export function readAnchors(dir) {
  return fs.readdirSync(dir)
    .filter((name) => /^attestation-.*\.json$/.test(name))
    .sort()
    .map((name) => {
      const parsed = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
      const attestation = parsed.attestation || parsed;
      // Timestamps live beside the anchor as <name>.<calendar>.ots. Reported
      // rather than required: the two mechanisms answer different questions,
      // and an anchor with no .ots is still a signed head we published. What
      // would be wrong is a verifier that knows about one of them and stays
      // quiet about the other.
      const timestamps = fs.readdirSync(dir)
        .filter((f) => f.startsWith(`${name}.`) && f.endsWith('.ots'));

      return {
        file: name,
        as_of: attestation.as_of,
        entries: Number(attestation.entries),
        head_hash: attestation.head_hash,
        signed: Boolean(parsed.signature),
        timestamps
      };
    });
}

export function compare(anchors, heads) {
  return anchors.map((anchor) => {
    if (!heads.has(anchor.entries)) {
      return {
        ...anchor, status: 'UNCHECKABLE',
        detail: `the ledger supplied stops at ${Math.max(...heads.keys())} entries, so entry ${anchor.entries} is not in it`
      };
    }
    const actual = heads.get(anchor.entries);
    return actual === anchor.head_hash
      ? { ...anchor, status: 'MATCH' }
      : { ...anchor, status: 'MISMATCH', actual, detail: 'history was rebuilt after this anchor was taken' };
  });
}

/* ------------------------------------------------------------------ CLI */
const invokedDirectly = process.argv[1] && process.argv[1].endsWith('verify-anchors.mjs');
if (invokedDirectly) {
  const args = process.argv.slice(2);

  // --anchors takes a value, and that value is not a flag. Finding the input
  // file by "first argument without a leading --" therefore picked the
  // directory when both were given, and the tool went off to read it as JSON.
  // The flag's value is excluded by position rather than by guessing at shapes.
  const anchorsAt = args.indexOf('--anchors');
  const anchorDir = anchorsAt > -1 ? args[anchorsAt + 1] : path.join(HERE, '..', 'anchors');
  if (anchorsAt > -1 && !anchorDir) {
    console.error('--anchors needs a directory after it');
    process.exit(2);
  }

  // Exclude --anchors's own value by position only when --anchors was found.
  // When it is absent, anchorsAt is -1 and anchorsAt + 1 is 0 — the index of
  // the file argument in the single most common invocation, which the
  // previous version of this line excluded by coincidence of arithmetic and
  // broke every plain "verify-anchors export.json" call with no test to catch
  // it, because the test suite only ever imports the pure functions below and
  // never runs this block.
  const file = args.find((a, i) => !a.startsWith('--') && !(anchorsAt > -1 && i === anchorsAt + 1));
  if (!file) {
    console.error('usage: node tools/verify-anchors.mjs <export.json|rows.json> [--anchors <dir>] [--skip-signatures]');
    process.exit(2);
  }

  const anchors = readAnchors(anchorDir);
  if (anchors.length === 0) {
    console.error(`No anchors found in ${anchorDir}. There is nothing to check history against.`);
    process.exit(2);
  }

  const results = compare(anchors, headsByCount(JSON.parse(fs.readFileSync(file, 'utf8'))));
  let bad = 0;

  for (const r of results) {
    const line = `${r.status.padEnd(11)} ${r.file}  ${String(r.entries).padStart(6)} entries  ${r.as_of}`;
    if (r.status === 'MATCH') {
      console.log(line);
    } else {
      bad++;
      console.error(line);
      console.error(`            ${r.detail}`);
      if (r.actual) {
        console.error(`            anchored ${r.head_hash}`);
        console.error(`            actual   ${r.actual}`);
      }
    }
    if (!r.signed) {
      console.error(`            this anchor carries no signature, so it proves only that someone had a text editor`);
    }
    if (r.timestamps.length === 0) {
      console.log(`            no third-party timestamp. Our own date is our own claim: npm run anchor:timestamp`);
    } else {
      console.log(`            timestamped by ${r.timestamps.length}: ${r.timestamps.map((f) => f.replace(`${r.file}.`, '').replace('.ots', '')).join(', ')}`);
      console.log(`            a fresh .ots is a submission; run 'ots upgrade' to make it a Bitcoin anchor`);
    }
  }

  if (!args.includes('--skip-signatures')) {
    console.log('');
    for (const r of results) {
      const out = spawnSync(process.execPath,
        [path.join(HERE, 'verify-attestation.mjs'), path.join(anchorDir, r.file)],
        { encoding: 'utf8' });
      if (out.status !== 0) {
        bad++;
        console.error(`SIGNATURE   ${r.file} did not verify`);
        console.error((out.stderr || out.stdout || '').trim().split('\n').map((l) => '            ' + l).join('\n'));
      } else {
        console.log(`SIGNATURE   ${r.file} verifies`);
      }
    }
  }

  console.log('');
  if (bad > 0) {
    console.error(`${bad} problem(s). Every anchored head must still come out of this ledger.`);
    process.exit(1);
  }
  console.log(`OK  ${results.length} anchor(s) still reproduced by this ledger.`);
}
