#!/usr/bin/env node
/**
 * Our log in the transparency-log network's formats. docs/transparency-log.md.
 *
 *   node tools/checkpoint.mjs keygen --out <dir> [--origin api.riskrouter.eu/tlog/evidence-v2]
 *   node tools/checkpoint.mjs verify <checkpoint.txt>... [--vkey <vkey or file>] [--witnesses <witnesses.json>]
 *   node tools/checkpoint.mjs mirror [--api https://api.riskrouter.eu] [--vkey <vkey or file>]
 *   node tools/checkpoint.mjs push   [--api https://api.riskrouter.eu] [--dir anchors/checkpoint]
 *
 * keygen   the log's Ed25519 checkpoint key, made once by
 *          .github/workflows/checkpoint-keygen.yml (docs/runbooks/checkpoint-key.md).
 *          Writes the private half to a
 *          file only its owner can read, and prints the public vkey.
 * verify   a saved checkpoint: our signature must verify; each cosignature from
 *          a witness in witnesses.json is checked too.
 * mirror   fetches the checkpoint and every tile it needs, and checks the
 *          tiles give its root: a hash mirror, all a monitor needs.
 * push     c2sp.org/tlog-witness: checks the current checkpoint against the
 *          last one we saved (a consistency proof, checked here), then posts
 *          it to each witness in witnesses.json and keeps only cosignatures
 *          that verify with that witness's key. Writes each file once:
 *            <dir>/cosigned/<size>/checkpoint.txt       our signed checkpoint
 *            <dir>/cosigned/<size>/<key id>.cosignature  one witness's line
 *          Exit 0 all well, 1 the checkpoint could not be read or verified,
 *          2 an alarm: our own log contradicted a checkpoint we saved, or a
 *          witness holds a larger tree than we serve.
 *
 * Operator tooling under rule 1: push runs from .github/workflows/checkpoint.yml
 * on a schedule; no request to our API can cause it to run.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ORIGIN, TYPE_ED25519, TYPE_COSIGNATURE_V1, newEd25519Key, parseVkey, verifyNote, parseCheckpoint,
  hexToB64, checkTiles
} from './note.mjs';
import { verifyConsistency, EMPTY_ROOT } from './merkle.mjs';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
export const DIR = path.join(ROOT, 'anchors', 'checkpoint');
const MAX_BODY = 64 * 1024;

/** A vkey given inline or as a file holding one. */
export function readVkey(value) {
  if (!value) return null;
  return fs.existsSync(value) ? fs.readFileSync(value, 'utf8').trim() : String(value).trim();
}

export function readWitnesses(file) {
  if (!file || !fs.existsSync(file)) return [];
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  return Array.isArray(doc.witnesses) ? doc.witnesses : [];
}

async function fetchText(fetchImpl, url, init = {}) {
  const r = await fetchImpl(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(20000) });
  const text = await r.text();
  if (text.length > MAX_BODY) throw new Error(`${url} answered more than ${MAX_BODY} bytes`);
  return { status: r.status, text, type: r.headers.get('content-type') || '' };
}

/** The current checkpoint, verified with our published key. */
export async function currentCheckpoint({ api, vkey, fetchImpl = fetch }) {
  const r = await fetchText(fetchImpl, `${api}/tlog/evidence-v2/checkpoint`);
  if (r.status !== 200) throw new Error(`the checkpoint answered ${r.status}: ${r.text.slice(0, 200)}`);
  const v = await verifyNote(r.text, [vkey]);
  if (!v.ok) throw new Error(`the checkpoint does not verify with our published key: ${v.reason}`);
  const cp = parseCheckpoint(v.text);
  const key = await parseVkey(vkey);
  if (cp.origin !== key.name) throw new Error(`the checkpoint names origin ${cp.origin}, not ${key.name}`);
  // Keep our own signature only: what we save and post is ours.
  return { ...cp, text: v.text, note: `${v.text}\n${v.verified[0].line}` };
}

const savedSizes = (dir) => (fs.existsSync(path.join(dir, 'cosigned'))
  ? fs.readdirSync(path.join(dir, 'cosigned')).filter((d) => /^(0|[1-9]\d*)$/.test(d)).map(Number).sort((a, b) => a - b) : []);

async function consistency(api, fetchImpl, first, second) {
  if (first === 0 || first === second) return [];
  const r = await fetchText(fetchImpl, `${api}/api/v2/evidence/consistency?first=${first}&second=${second}`, { headers: { Accept: 'application/json' } });
  if (r.status !== 200) throw new Error(`the consistency proof from ${first} to ${second} answered ${r.status}`);
  const proof = JSON.parse(r.text).proof;
  if (!Array.isArray(proof) || proof.length > 63 || !proof.every((h) => /^[0-9a-f]{64}$/.test(h))) throw new Error('the consistency proof is malformed');
  return proof;
}

/** One witness, one checkpoint: the add-checkpoint call, with one retry on 409. Returns verified cosignature lines. */
export async function addCheckpoint({ witness, cp, old, api, fetchImpl = fetch }) {
  const key = await parseVkey(witness.vkey);
  if (key.type !== TYPE_COSIGNATURE_V1) throw new Error(`${witness.name}: a witness key has type 0x04`);
  for (let attempt = 0; attempt < 2; attempt++) {
    const proof = await consistency(api, fetchImpl, old, cp.tree_size);
    const body = `old ${old}\n${proof.map((h) => `${hexToB64(h)}\n`).join('')}\n${cp.note}`;
    const r = await fetchText(fetchImpl, witness.url, { method: 'POST', body, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    if (r.status === 409) {
      const theirs = Number((r.text.match(/^(0|[1-9]\d*)\n?$/) || [])[1]);
      if (!Number.isSafeInteger(theirs)) throw new Error(`${witness.name}: 409 without a size`);
      if (theirs > cp.tree_size) return { alarm: `${witness.name} has cosigned a tree of ${theirs} leaves, larger than the ${cp.tree_size} we serve` };
      if (theirs === old) throw new Error(`${witness.name}: 409 at the size we sent`);
      old = theirs;
      continue;
    }
    if (r.status !== 200) throw new Error(`${witness.name}: add-checkpoint answered ${r.status}: ${r.text.slice(0, 200)}`);
    const lines = r.text.split('\n').filter((l) => l.startsWith('— ')).map((l) => `${l}\n`);
    const kept = [];
    for (const line of lines) {
      const v = await verifyNote(`${cp.text}\n${line}`, [key]);
      if (v.ok) kept.push({ line, timestamp: v.verified[0].timestamp });
    }
    if (!kept.length) throw new Error(`${witness.name}: no cosignature verified with its published key`);
    return { cosignatures: kept, id: key.id };
  }
  throw new Error(`${witness.name}: 409 twice`);
}

/** The push round. Returns { code, lines }. */
export async function push({ api = 'https://api.riskrouter.eu', dir = DIR, fetchImpl = fetch, log = console.log } = {}) {
  const vkeyFile = path.join(dir, 'log.vkey');
  const vkey = fs.existsSync(vkeyFile) ? fs.readFileSync(vkeyFile, 'utf8').trim() : null;
  if (!vkey) { log('No checkpoint key is published yet (anchors/checkpoint/log.vkey); nothing to push.'); return { code: 0 }; }
  const cp = await currentCheckpoint({ api, vkey, fetchImpl });
  log(`checkpoint  tree_size ${cp.tree_size}  root ${cp.root_hash}`);

  const sizes = savedSizes(dir);
  const last = sizes.at(-1);
  if (last !== undefined) {
    const saved = parseCheckpoint((await verifyNote(fs.readFileSync(path.join(dir, 'cosigned', String(last), 'checkpoint.txt'), 'utf8'), [vkey])).text);
    // The empty tree is a prefix of every tree; any other saved size needs a proof, checked here.
    const consistent = cp.tree_size === saved.tree_size ? cp.root_hash === saved.root_hash
      : cp.tree_size > saved.tree_size && (saved.tree_size === 0 ? saved.root_hash === EMPTY_ROOT
        : await verifyConsistency(saved.tree_size, cp.tree_size, saved.root_hash, cp.root_hash, await consistency(api, fetchImpl, saved.tree_size, cp.tree_size)));
    if (!consistent) {
      const alarm = path.join(dir, `ALARM-${Date.now()}.txt`);
      fs.writeFileSync(alarm, `saved:\n${fs.readFileSync(path.join(dir, 'cosigned', String(last), 'checkpoint.txt'), 'utf8')}\nserved:\n${cp.note}`);
      log(`ALARM: the checkpoint we serve now is not consistent with tree_size ${saved.tree_size}, which we saved. Both are in ${alarm}.`);
      return { code: 2 };
    }
  }
  const here = path.join(dir, 'cosigned', String(cp.tree_size));
  fs.mkdirSync(here, { recursive: true });
  if (!fs.existsSync(path.join(here, 'checkpoint.txt'))) fs.writeFileSync(path.join(here, 'checkpoint.txt'), cp.note, { flag: 'wx' });

  let code = 0;
  const witnesses = readWitnesses(path.join(dir, 'witnesses.json'));
  if (!witnesses.length) log('No witness is configured yet (anchors/checkpoint/witnesses.json).');
  for (const witness of witnesses) {
    try {
      const { id } = await parseVkey(witness.vkey);
      const file = path.join(here, `${id}.cosignature`);
      if (fs.existsSync(file)) { log(`unchanged   ${witness.name} already cosigned tree_size ${cp.tree_size}`); continue; }
      const old = savedSizes(dir).filter((s) => s <= cp.tree_size && fs.existsSync(path.join(dir, 'cosigned', String(s), `${id}.cosignature`))).at(-1) ?? 0;
      const r = await addCheckpoint({ witness, cp, old, api, fetchImpl });
      if (r.alarm) { log(`ALARM: ${r.alarm}`); code = 2; continue; }
      fs.writeFileSync(file, r.cosignatures.map((c) => c.line).join(''), { flag: 'wx' });
      log(`cosigned    ${witness.name} at ${new Date(r.cosignatures[0].timestamp * 1000).toISOString()}`);
    } catch (e) {
      log(`skipped     ${witness.name}: ${e.message}`);
    }
  }
  return { code };
}

/** Check a saved checkpoint directory entry, or any note file: ours must verify; known witnesses too. */
export async function verifyFile(file, { vkey, witnesses = [] }) {
  const lines = [];
  let note = fs.readFileSync(file, 'utf8');
  const dir = path.dirname(file);
  if (path.basename(file) === 'checkpoint.txt') {
    for (const f of fs.readdirSync(dir).filter((n) => n.endsWith('.cosignature')).sort()) note += fs.readFileSync(path.join(dir, f), 'utf8');
  }
  const ours = await verifyNote(note, [vkey]);
  lines.push({ ok: ours.ok, line: ours.ok ? `our signature holds: ${JSON.stringify(parseCheckpoint(ours.text))}` : ours.reason });
  if (!ours.ok) return lines;
  for (const w of witnesses) {
    const key = await parseVkey(w.vkey);
    const parsed = note.split('\n').filter((l) => l.startsWith(`— ${key.name} `));
    if (!parsed.length) continue;
    const v = await verifyNote(`${ours.text}\n${parsed.map((l) => `${l}\n`).join('')}`, [key]);
    lines.push({ ok: v.ok, line: v.ok ? `${w.name} cosigned it at ${new Date(v.verified[0].timestamp * 1000).toISOString()}` : `${w.name}: ${v.reason}` });
  }
  return lines;
}

/* ------------------------------------------------------------------ CLI */

async function main(argv) {
  const arg = (n, d) => { const i = argv.indexOf(`--${n}`); return i === -1 ? d : argv[i + 1]; };
  const fail = (m, code = 1) => { console.error(m); process.exit(code); };
  const api = arg('api', 'https://api.riskrouter.eu').replace(/\/+$/, '');
  const command = argv[0];

  if (command === 'keygen') {
    const out = arg('out');
    if (!out) fail('usage: node tools/checkpoint.mjs keygen --out <dir> [--origin <origin>]');
    const origin = arg('origin', ORIGIN);
    const file = path.join(out, 'checkpoint-key.pkcs8.b64');
    if (fs.existsSync(file)) fail(`${file} exists; refusing to replace a key`);
    const { private_pkcs8_b64, signer } = await newEd25519Key(origin, TYPE_ED25519);
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(file, private_pkcs8_b64 + '\n', { mode: 0o600, flag: 'wx' });
    console.log(signer.vkey);
    console.error(`\nThe private key is in ${file}, readable by you only. Next (docs/runbooks/checkpoint-key.md):`);
    console.error(`  echo '${signer.vkey}' > anchors/checkpoint/log.vkey`);
    console.error(`  set CHECKPOINT_VKEY = "${signer.vkey}" in wrangler.toml`);
    console.error(`  npx wrangler secret put CHECKPOINT_SIGNING_KEY < ${file}`);
    console.error(`  then delete ${file}. Commit and push; CI deploys.`);
    return;
  }

  if (command === 'verify') {
    const files = argv.slice(1).filter((a, i, all) => !a.startsWith('--') && !(all[i - 1] || '').startsWith('--'));
    const vkey = readVkey(arg('vkey') ?? (fs.existsSync(path.join(DIR, 'log.vkey')) ? path.join(DIR, 'log.vkey') : null));
    if (!files.length || !vkey) fail('usage: node tools/checkpoint.mjs verify <checkpoint.txt>... [--vkey <vkey or file>] [--witnesses <file>]');
    const witnesses = readWitnesses(arg('witnesses', path.join(DIR, 'witnesses.json')));
    let bad = false;
    for (const f of files) {
      for (const l of await verifyFile(f, { vkey, witnesses })) { console.log(`${l.ok ? 'OK  ' : 'FAIL'}  ${f}: ${l.line}`); bad ||= !l.ok; }
    }
    process.exit(bad ? 1 : 0);
  }

  if (command === 'mirror') {
    const vkey = readVkey(arg('vkey') ?? (fs.existsSync(path.join(DIR, 'log.vkey')) ? path.join(DIR, 'log.vkey') : null));
    if (!vkey) fail('mirror needs the log\'s vkey: --vkey <vkey or file>');
    const cp = await currentCheckpoint({ api, vkey });
    const r = await checkTiles({ tree_size: cp.tree_size, root_hash: cp.root_hash, getTile: async (p) => {
      const res = await fetch(`${api}/tlog/evidence-v2/${p}`, { redirect: 'error', signal: AbortSignal.timeout(20000) });
      if (res.status !== 200) throw new Error(`${p} answered ${res.status}`);
      return new Uint8Array(await res.arrayBuffer());
    } });
    console.log(`OK    ${r.tiles} tiles, ${r.leaves} leaf hashes, give root ${r.root_hash} of the checkpoint at tree_size ${r.tree_size}`);
    return;
  }

  if (command === 'push') {
    const { code } = await push({ api, dir: arg('dir', DIR) });
    process.exit(code);
  }

  fail('usage: node tools/checkpoint.mjs keygen|verify|mirror|push  (see the top of this file)');
}

if (process.argv[1] && process.argv[1].endsWith('checkpoint.mjs')) {
  main(process.argv.slice(2)).catch((e) => { console.error(e.message); process.exit(1); });
}
