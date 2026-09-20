#!/usr/bin/env node
/**
 * Checks a saved RiskRouter attestation against the published signing key.
 *
 * The chain proves history has not been edited. It cannot prove history was not
 * rebuilt from scratch, because a rebuild recomputes every digest consistently.
 * The defence against that is holding an earlier head hash — and a head hash is
 * only an argument if the operator cannot deny having published it.
 *
 * That is what this checks. It shares no code with the Worker that produced the
 * signature, and it never contacts RiskRouter: it reads a file you saved and a
 * key you already have.
 *
 *   node tools/verify-attestation.mjs saved-attestation.json
 *   node tools/verify-attestation.mjs saved.json --key anchors/signing-key.json
 *
 * A verified attestation means: this operator asserted this head hash, with
 * this entry count, at this time, and cannot now say otherwise. It does NOT
 * mean the ledger is intact today — for that, export the rows and run
 * tools/verify-ledger.mjs --expect-head <the head hash this file carries>.
 */
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

function fail(message) {
  console.error(`FAIL  ${message}`);
  process.exit(1);
}

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--'));
const keyIndex = args.indexOf('--key');
const keyFile = keyIndex === -1 ? path.join(ROOT, 'anchors', 'signing-key.json') : args[keyIndex + 1];

if (!file) fail('usage: node tools/verify-attestation.mjs <saved-attestation.json> [--key anchors/signing-key.json]');

const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
const published = JSON.parse(fs.readFileSync(keyFile, 'utf8'));

const attestation = saved.attestation || saved;
const signature = saved.signature;
if (!signature) fail('this file carries no signature, so it proves only that someone had a text editor');

/* Rebuild the signed bytes from the attestation itself rather than trusting the
   signed_payload field. A file that carries a signature over some other string
   would otherwise verify while saying whatever it liked. */
const rebuilt = [
  'riskrouter-ledger-attestation',
  'v1',
  String(attestation.as_of ?? ''),
  String(attestation.entries ?? ''),
  String(attestation.head_hash ?? '')
].join('|');

if (signature.signed_payload && signature.signed_payload !== rebuilt) {
  fail(`the signature covers different content than this file claims\n  signed:   ${signature.signed_payload}\n  rebuilt:  ${rebuilt}`);
}

if (signature.key_id && published.key_id && signature.key_id !== published.key_id) {
  fail(`signed with key ${signature.key_id}, but the key supplied is ${published.key_id}`);
}

const key = crypto.createPublicKey({ key: published.public_key, format: 'jwk' });
const ok = crypto.verify(
  'sha256',
  Buffer.from(rebuilt, 'utf8'),
  { key, dsaEncoding: 'ieee-p1363' },
  Buffer.from(signature.signature, 'base64')
);

if (!ok) fail('the signature does not verify against this key');

console.log('OK    signature verifies');
console.log(`      entries    ${attestation.entries}`);
console.log(`      head_hash  ${attestation.head_hash}`);
console.log(`      as of      ${attestation.as_of}`);
console.log(`      key        ${published.key_id || '(unnamed)'}  ${published.algorithm || ''}`);
console.log('');
console.log('This proves the operator published this head hash at this time and cannot disown it.');
console.log('It does not prove the ledger is intact today. For that:');
console.log(`  node tools/verify-ledger.mjs rows.json --expect-head ${attestation.head_hash}`);
