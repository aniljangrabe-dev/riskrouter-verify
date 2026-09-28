/**
 * The witness as a Cloudflare Worker, run on the WITNESS's own account with a
 * key the witness generated. docs/witness-network.md, witness/README.md.
 *
 * Two halves, kept apart on purpose:
 *
 *   scheduled()  an hourly Cron Trigger runs one round: every configured log,
 *                and every log in the registry if FOLLOW_REGISTRY is set.
 *                This is the only code path that calls a log.
 *   fetch()      serves what the rounds stored, read-only: the public key, the
 *                latest cosignature per log, any alarm. It never calls out,
 *                never runs a round, never writes, whoever asks and however
 *                often, so the witness cannot be driven by a stranger.
 *
 * Bindings (witness/wrangler.toml.example):
 *   WITNESS_STATE        KV namespace: state, pinned keys, cosignatures, alarms
 *   WITNESS_PRIVATE_KEY  secret: the witness key, base64 PKCS#8 (node witness/node.mjs init)
 *   WITNESS_NAME         who runs this witness, as it should be shown
 *   WITNESS_LOGS         optional JSON array of logs: [{ "id", "api", "keys": [...] }]
 *   FOLLOW_REGISTRY      optional URL of a registry, e.g. https://riskrouter.eu/registry.json
 */
import { runWitness, loadSigner, serveRequest } from './core.mjs';

/** The witness's KV namespace, behind the core's get/put interface. Keys are the published paths. */
export function kvStore(kv) {
  return {
    get: (path) => kv.get(path, 'json'),
    put: (path, value) => kv.put(path, JSON.stringify(value))
  };
}

async function signerFrom(env) {
  if (!env.WITNESS_PRIVATE_KEY) return null;
  const signer = await loadSigner(env.WITNESS_PRIVATE_KEY);
  signer.name = env.WITNESS_NAME || null;
  return signer;
}

function configuredLogs(env) {
  if (!env.WITNESS_LOGS) return [];
  const logs = JSON.parse(env.WITNESS_LOGS);
  if (!Array.isArray(logs)) throw new Error('WITNESS_LOGS must be a JSON array of logs');
  return logs;
}

/** One round, as the Cron Trigger runs it. `fetchImpl` is the network; only this path is given it. */
export async function round(env, { fetchImpl = fetch, now } = {}) {
  const signer = await signerFrom(env);
  if (!signer) throw new Error('WITNESS_PRIVATE_KEY is not set: run node witness/node.mjs init and add the key as a secret');
  const results = await runWitness({
    configured: configuredLogs(env),
    registryUrl: env.FOLLOW_REGISTRY || null,
    fetchImpl,
    store: kvStore(env.WITNESS_STATE),
    signer,
    ...(now ? { now } : {})
  });
  for (const r of results) console.log(`${r.status.padEnd(9)} ${r.log}${r.tree_size != null ? ` tree_size ${r.tree_size}` : ''}${r.reason ? `: ${r.reason}` : ''}`);
  return results;
}

export default {
  async fetch(request, env) {
    const signer = await signerFrom(env).catch(() => null);
    const published = signer
      ? { witness_id: signer.witness_id, name: signer.name, algorithm: 'ECDSA_P256_SHA256', public_key: signer.public_key }
      : null;
    return serveRequest(request, { store: kvStore(env.WITNESS_STATE), published });
  },

  async scheduled(controller, env, ctx) {
    ctx.waitUntil(round(env));
  }
};
