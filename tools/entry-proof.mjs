#!/usr/bin/env node
/**
 * Cut a single-entry proof out of a ledger export.
 *
 *   node tools/entry-proof.mjs export.json <chain_index|id> > proof.json
 *
 * For showing one quote to a regulator, an auditor or a customer without
 * handing over every other quote you recorded. What the proof does and does
 * not establish is set out beside verifyEntryProof() in verify-ledger.mjs.
 * The same extraction runs in the browser on https://riskrouter.eu/verify.
 */
import fs from 'node:fs';
import { makeEntryProof, verifyEntryProof } from './verify-ledger.mjs';

const [file, which] = process.argv.slice(2);
if (!file || !which) {
  console.error('usage: node tools/entry-proof.mjs <export.json> <chain_index|id> > proof.json');
  process.exit(2);
}
let proof;
try {
  proof = makeEntryProof(JSON.parse(fs.readFileSync(file, 'utf8')), which);
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
const check = verifyEntryProof(proof);
if (!check.intact) {
  console.error(`refusing to write a proof that does not verify: ${check.reason}`);
  process.exit(1);
}
process.stdout.write(JSON.stringify(proof, null, 2) + '\n');
