#!/usr/bin/env node
/**
 * The witness as a command, storing its state in a directory. witness/README.md.
 *
 *   node witness/node.mjs init --out ./my-witness --name "Your organisation"
 *   node witness/node.mjs run  --state ./my-witness/published [--config witness.config.json]
 *                              [--every 3600] [--port 8080]
 *
 * `init` writes the witness key: private-key.b64 (keep it secret: a secret in
 * your CI, a file only you can read) and public-key.json (publish it).
 *
 * `run` does one round and exits: 0 when all is well, 2 when an alarm stands
 * for any log (the evidence is in <state>/alarms/), 1 when no log could be
 * co-signed. With --every it repeats; with --port it also serves the state
 * directory read-only, exactly as the Worker does. The state directory is
 * meant to be published: it holds the latest cosignature per log, any alarm,
 * the heads seen and the keys pinned, and never the private key.
 *
 * Configuration, from --config or the environment (the Worker's names):
 *   name / WITNESS_NAME, logs / WITNESS_LOGS (JSON), follow_registry / FOLLOW_REGISTRY.
 * The key: WITNESS_PRIVATE_KEY, or --key <private-key.b64>.
 *
 * Operator tooling under rule 1: it runs on the witness's machine, on its
 * schedule. The HTTP side, when served, never calls out.
 */
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { newWitnessKey, loadSigner, runWitness, serveRequest } from './core.mjs';

/** A directory behind the core's get/put interface. Writes are atomic (a temp file, then rename). */
export function directoryStore(dir) {
  const file = (p) => {
    const f = path.resolve(dir, p);
    if (!f.startsWith(path.resolve(dir) + path.sep)) throw new Error(`refusing a path outside the state directory: ${p}`);
    return f;
  };
  return {
    async get(p) {
      try { return JSON.parse(fs.readFileSync(file(p), 'utf8')); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
    },
    async put(p, value) {
      const f = file(p);
      fs.mkdirSync(path.dirname(f), { recursive: true });
      const tmp = `${f}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n');
      fs.renameSync(tmp, f);
    }
  };
}

/** The configuration, from a file if given, else from the environment. */
export function loadConfig({ configFile, env = process.env }) {
  const c = configFile ? JSON.parse(fs.readFileSync(configFile, 'utf8')) : {};
  const logs = c.logs ?? (env.WITNESS_LOGS ? JSON.parse(env.WITNESS_LOGS) : []);
  if (!Array.isArray(logs)) throw new Error('logs must be a JSON array');
  return {
    name: c.name ?? env.WITNESS_NAME ?? null,
    logs,
    follow_registry: c.follow_registry !== undefined ? c.follow_registry : (env.FOLLOW_REGISTRY || null)
  };
}

export async function signerFor({ keyFile, env = process.env, name }) {
  const b64 = (keyFile ? fs.readFileSync(keyFile, 'utf8') : env.WITNESS_PRIVATE_KEY || '').trim();
  if (!b64) throw new Error('no witness key: set WITNESS_PRIVATE_KEY or pass --key <private-key.b64> (node witness/node.mjs init makes one)');
  const signer = await loadSigner(b64);
  signer.name = name || null;
  return signer;
}

const publishedOf = (signer) => ({ witness_id: signer.witness_id, name: signer.name, algorithm: 'ECDSA_P256_SHA256', public_key: signer.public_key });

/** One round into a directory. Returns the results and the exit code a scheduler should see. */
export async function runOnce({ config, stateDir, signer, fetchImpl = fetch, now, log = console.log }) {
  const store = directoryStore(stateDir);
  await store.put('public-key.json', publishedOf(signer));
  const results = await runWitness({ configured: config.logs, registryUrl: config.follow_registry, fetchImpl, store, signer, ...(now ? { now } : {}) });
  for (const r of results) log(`${r.status.padEnd(9)} ${r.log}${r.tree_size != null ? ` tree_size ${r.tree_size}` : ''}${r.reason ? `: ${r.reason}` : ''}`);
  const code = results.some((r) => r.status === 'alarm' || r.status === 'halted') ? 2
    : results.some((r) => r.status === 'cosigned') ? 0 : 1;
  return { results, code };
}

/** The state directory, served read-only through the same handler as the Worker. */
export function serve({ stateDir, signer, port, host = '0.0.0.0' }) {
  const store = directoryStore(stateDir);
  const server = http.createServer(async (req, res) => {
    try {
      const response = await serveRequest(new Request(`http://witness${req.url}`, { method: req.method }), { store, published: publishedOf(signer) });
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(req.method === 'HEAD' ? undefined : Buffer.from(await response.arrayBuffer()));
    } catch {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end('{"error":"internal error"}\n');
    }
  });
  return new Promise((resolve) => server.listen(port, host, () => resolve(server)));
}

/* ------------------------------------------------------------------ CLI */

async function main(argv) {
  const arg = (n, d) => { const i = argv.indexOf(`--${n}`); return i === -1 ? d : argv[i + 1]; };
  const fail = (m, code = 1) => { console.error(m); process.exit(code); };
  const command = argv[0];

  if (command === 'init') {
    const out = arg('out');
    const name = arg('name');
    if (!out || !name) fail('usage: node witness/node.mjs init --out <dir> --name "<who you are>"');
    const priv = path.join(out, 'private-key.b64');
    if (fs.existsSync(priv)) fail(`${priv} exists; refusing to replace a witness key`);
    const key = await newWitnessKey(name);
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(priv, key.private_pkcs8_b64 + '\n', { mode: 0o600, flag: 'wx' });
    fs.writeFileSync(path.join(out, 'public-key.json'), JSON.stringify(key.published, null, 2) + '\n', { flag: 'wx' });
    console.log(`witness ${key.published.witness_id} created in ${out}`);
    console.log(`  ${priv}: the private key. Put it in a secret (WITNESS_PRIVATE_KEY); never commit or share it.`);
    console.log(`  ${path.join(out, 'public-key.json')}: publish it somewhere under your control, and send it to be listed.`);
    return;
  }

  if (command === 'run') {
    const stateDir = arg('state');
    if (!stateDir) fail('usage: node witness/node.mjs run --state <dir> [--config <file>] [--key <file>] [--every <seconds>] [--port <port>]');
    const config = loadConfig({ configFile: arg('config') });
    if (!config.logs.length && !config.follow_registry) fail('nothing to witness: configure logs, or follow a registry');
    const signer = await signerFor({ keyFile: arg('key'), name: config.name });
    const every = Number(arg('every', 0));
    const port = arg('port');
    if (port) {
      await serve({ stateDir, signer, port: Number(port) });
      console.log(`serving ${stateDir} read-only on port ${port}`);
    }
    if (!every) {
      const { code } = await runOnce({ config, stateDir, signer });
      if (!port) process.exit(code);
      return;
    }
    if (every < 60) fail('--every is in seconds, at least 60');
    for (;;) {
      await runOnce({ config, stateDir, signer }).catch((e) => console.error(`round failed: ${e.message}`));
      await new Promise((r) => setTimeout(r, every * 1000));
    }
  }

  fail('usage: node witness/node.mjs init|run  (see the top of this file)');
}

if (process.argv[1] && process.argv[1].endsWith('node.mjs')) main(process.argv.slice(2));
