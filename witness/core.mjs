/**
 * The witness, as one portable core. docs/witness-network.md.
 *
 * WebCrypto only, no Node APIs, so the same code runs as a Cloudflare Worker
 * (witness/worker.js), as a command (witness/node.mjs) and in GitHub Actions.
 *
 * One round, for every log the witness follows: fetch the current signed head,
 * check the log's signature with a key the witness has pinned, and if the log
 * has grown since the head it saved, check a consistency proof against the
 * root IT saved, never one the log supplies. Only if every check passes does
 * it co-sign, with its own key, in the existing format:
 *
 *   riskrouter-evidence-cosign|v2|witness_id|tree_size|root_hash|cosigned_at
 *
 * If a log contradicts a head the witness saw, the witness stops co-signing
 * that log for good, and keeps both signed heads where anyone can read them.
 *
 * Storage is a small interface, get(path) and put(path, value), whose paths
 * are the paths the witness publishes:
 *
 *   cosignatures/<log>/latest.json   the latest cosignature of that log
 *   alarms/<log>.json                the evidence, if the log was caught rewriting history
 *   state/<log>.json                 the last head it saw (private working state)
 *   pinned/<log>.json                the log's keys, pinned on first sight
 *   logs.json                        which logs it witnesses
 */
import { verifyConsistency, headPayload } from '../tools/merkle.mjs';

export const COSIGNATURE_FORMAT = 'riskrouter-evidence-cosignature|v2';
export const LOG_ID = /^[a-z0-9][a-z0-9-]{1,39}$/;

export function cosignPayload({ witness_id, tree_size, root_hash, cosigned_at }) {
  return ['riskrouter-evidence-cosign', 'v2', witness_id, String(tree_size), root_hash, cosigned_at].join('|');
}

const bytesToB64 = (bytes) => { let s = ''; for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b); return btoa(s); };
const b64ToBytes = (b64) => Uint8Array.from(atob(String(b64)), (c) => c.charCodeAt(0));
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const P256 = { name: 'ECDSA', namedCurve: 'P-256' };

/** A witness id: the first 16 hex characters of SHA-256 over JSON [x, y], as tools/witness.mjs derives it. */
export async function witnessIdOf(jwk) {
  return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify([jwk.x, jwk.y])))).slice(0, 16);
}

/** The witness's own key, from its PKCS#8 private half (base64). Signs cosignature payloads, raw r||s. */
export async function loadSigner(pkcs8B64) {
  const der = b64ToBytes(pkcs8B64);
  const jwk = await crypto.subtle.exportKey('jwk', await crypto.subtle.importKey('pkcs8', der, P256, true, ['sign']));
  const key = await crypto.subtle.importKey('pkcs8', der, P256, false, ['sign']);
  const public_key = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  return {
    public_key,
    witness_id: await witnessIdOf(public_key),
    async sign(payload) {
      return bytesToB64(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(payload)));
    }
  };
}

/** A new witness key: the private half to keep secret, the public half to publish. */
export async function newWitnessKey(name) {
  const pair = await crypto.subtle.generateKey(P256, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const public_key = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  return {
    private_pkcs8_b64: bytesToB64(await crypto.subtle.exportKey('pkcs8', pair.privateKey)),
    published: { witness_id: await witnessIdOf(public_key), name, algorithm: 'ECDSA_P256_SHA256', public_key }
  };
}

async function verifyP256(jwk, payload, signatureB64) {
  try {
    const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, P256, false, ['verify']);
    return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64ToBytes(signatureB64), new TextEncoder().encode(payload));
  } catch {
    return false;
  }
}

/** The log's signature on a head, rebuilt from the head itself, with one of the log's keys. */
export async function verifyHead(body, keys) {
  if (!body?.head || !body?.signature?.signature) return { ok: false, reason: 'the head carries no signature' };
  const payload = headPayload(body.head);
  if (body.signature.signed_payload && body.signature.signed_payload !== payload) {
    return { ok: false, reason: 'the signature covers different content than the head claims' };
  }
  const key = keys.find((k) => k.key_id === body.signature.key_id) || (keys.length === 1 && !keys[0].key_id ? keys[0] : null);
  if (!key) return { ok: false, reason: `signed with key ${body.signature.key_id || '(unnamed)'}, which is not a key this witness holds for the log` };
  return await verifyP256(key.public_key, payload, body.signature.signature)
    ? { ok: true } : { ok: false, reason: 'the head signature does not verify with the log\'s key' };
}

const sameKey = (a, b) => a.key_id === b.key_id && a.public_key?.x === b.public_key?.x && a.public_key?.y === b.public_key?.y;
const isPrivateHost = (h) => h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.internal') || h.endsWith('.local') ||
  /^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h) || /^169\.254\./.test(h) ||
  /^0\./.test(h) || h.startsWith('[') || !h.includes('.');

function checkLog(log) {
  if (!log || !LOG_ID.test(String(log.id))) return 'a log needs an id: lower-case letters, digits and hyphens';
  let url;
  try { url = new URL(log.api); } catch { return `log ${log.id}: api is not a URL`; }
  // A log on a private network (the api service of a self-hosted stack) may be
  // configured by the witness itself, never offered by a registry: a registry
  // that could point a witness at private addresses could use it to probe them.
  const privateOk = log.source === 'configured' && isPrivateHost(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && privateOk)) return `log ${log.id}: api must be https`;
  if (isPrivateHost(url.hostname) && !privateOk) return `log ${log.id}: a registry may not point a witness at a private address`;
  if (url.username || url.password || url.search || url.hash) return `log ${log.id}: api must be a plain base URL`;
  if (!Array.isArray(log.keys) || !log.keys.length || !log.keys.every((k) => k?.public_key?.x && k?.public_key?.y)) return `log ${log.id}: needs at least one public key`;
  return null;
}

/**
 * The logs to witness this round: those configured, and, when following a
 * registry, every log it lists. Keys are pinned on first sight; a later list
 * may add a key (a rotation) but never drop or change a pinned one.
 */
export async function resolveLogs({ configured = [], registryUrl = null, fetchImpl, store, now = () => new Date() }) {
  const results = [];
  let candidates = configured.map((l) => ({ ...l, source: 'configured' }));
  if (registryUrl) {
    try {
      const r = await fetchImpl(registryUrl, { headers: { Accept: 'application/json' } });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const reg = await r.json();
      for (const l of reg.logs || []) {
        if (!candidates.some((c) => c.id === l.id)) candidates.push({ id: l.id, name: l.name, api: l.api, keys: l.keys, source: 'registry' });
      }
    } catch (e) {
      results.push({ log: '(registry)', status: 'warning', reason: `the registry could not be read (${e.message}); witnessing the configured logs only` });
    }
  }
  const logs = [];
  for (const log of candidates) {
    const problem = checkLog(log);
    if (problem) { results.push({ log: log.id || '(unnamed)', status: 'refused', reason: problem }); continue; }
    const pinned = await store.get(`pinned/${log.id}.json`);
    if (!pinned) {
      await store.put(`pinned/${log.id}.json`, { keys: log.keys, pinned_at: now().toISOString(), source: log.source });
      logs.push(log);
      continue;
    }
    const dropped = pinned.keys.filter((p) => !log.keys.some((k) => sameKey(k, p)));
    if (dropped.length) {
      await raiseAlarm(store, log.id, now, `${log.source === 'registry' ? 'the registry' : 'the configuration'} dropped or changed a key this witness pinned (${dropped.map((k) => k.key_id).join(', ')})`, { pinned, offered: log.keys });
      results.push({ log: log.id, status: 'alarm', reason: 'a pinned key was dropped or changed' });
      continue;
    }
    const added = log.keys.filter((k) => !pinned.keys.some((p) => sameKey(k, p)));
    if (added.length) await store.put(`pinned/${log.id}.json`, { ...pinned, keys: [...pinned.keys, ...added] });
    logs.push({ ...log, keys: [...pinned.keys, ...added] });
  }
  return { logs, results };
}

async function raiseAlarm(store, logId, now, reason, evidence) {
  // Never overwritten: the first contradiction is the evidence.
  if (await store.get(`alarms/${logId}.json`)) return;
  await store.put(`alarms/${logId}.json`, { log: logId, raised_at: now().toISOString(), reason, evidence });
}

/** One log, one round. Returns { log, status: cosigned | refused | alarm | halted, ... }. */
export async function witnessLog({ log, fetchImpl, store, signer, now = () => new Date() }) {
  if (await store.get(`alarms/${log.id}.json`)) {
    return { log: log.id, status: 'halted', reason: 'an alarm stands for this log; this witness no longer co-signs it' };
  }
  const get = async (p) => {
    const r = await fetchImpl(log.api.replace(/\/+$/, '') + p, { headers: { Accept: 'application/json' } });
    if (!r.ok) throw new Error(`${p} answered ${r.status}`);
    return r.json();
  };
  let current;
  try { current = await get('/api/v2/evidence/head'); } catch (e) { return { log: log.id, status: 'refused', reason: `the head could not be read (${e.message})` }; }
  const sig = await verifyHead(current, log.keys);
  if (!sig.ok) return { log: log.id, status: 'refused', reason: sig.reason };
  const head = current.head;
  const state = await store.get(`state/${log.id}.json`);
  let checked = 'first head this witness has seen of this log; nothing earlier to check it against';
  if (state) {
    const last = state.head;
    const alarm = async (reason, evidence) => {
      await raiseAlarm(store, log.id, now, reason, evidence);
      return { log: log.id, status: 'alarm', reason };
    };
    if (head.tree_size < last.tree_size) return alarm('the log shrank below a head this witness saw', { saved: state, now: current });
    if (head.tree_size === last.tree_size && head.root_hash !== last.root_hash) {
      return alarm('two signed heads of the same size with different roots', { saved: state, now: current });
    }
    if (head.tree_size > last.tree_size) {
      let proof;
      try { proof = await get(`/api/v2/evidence/consistency?first=${last.tree_size}&second=${head.tree_size}`); } catch (e) {
        return { log: log.id, status: 'refused', reason: `the consistency proof could not be read (${e.message})` };
      }
      if (!await verifyConsistency(last.tree_size, head.tree_size, last.root_hash, head.root_hash, proof.proof || [])) {
        return alarm('the current head is not consistent with a head this witness saw', { saved: state, now: current, proof });
      }
    }
    checked = `consistent with tree_size ${last.tree_size} (root ${last.root_hash}), which this witness saw earlier`;
  }
  const cosigned_at = now().toISOString();
  const payload = cosignPayload({ witness_id: signer.witness_id, tree_size: head.tree_size, root_hash: head.root_hash, cosigned_at });
  const doc = {
    format: COSIGNATURE_FORMAT,
    witness_id: signer.witness_id,
    witness_name: signer.name || null,
    log: { id: log.id, api: log.api },
    head,
    head_signature: current.signature,
    cosigned_at,
    cosignature: { algorithm: 'ECDSA_P256_SHA256', signed_payload: payload, signature: await signer.sign(payload) },
    checked
  };
  await store.put(`cosignatures/${log.id}/latest.json`, doc);
  await store.put(`state/${log.id}.json`, { head, signature: current.signature, seen_at: cosigned_at });
  return { log: log.id, status: 'cosigned', tree_size: head.tree_size, checked };
}

/** A whole round: resolve the logs, witness each, record which logs this witness follows. */
export async function runWitness({ configured = [], registryUrl = null, fetchImpl, store, signer, now = () => new Date() }) {
  const { logs, results } = await resolveLogs({ configured, registryUrl, fetchImpl, store, now });
  for (const log of logs) {
    try {
      results.push(await witnessLog({ log, fetchImpl, store, signer, now }));
    } catch (e) {
      results.push({ log: log.id, status: 'refused', reason: String(e?.message || e).slice(0, 200) });
    }
  }
  const api = new Map(logs.map((l) => [l.id, l.api]));
  await store.put('logs.json', {
    witness_id: signer.witness_id,
    round_at: now().toISOString(),
    logs: results.filter((r) => LOG_ID.test(r.log)).map((r) => ({ id: r.log, api: api.get(r.log) || null, status: r.status, ...(r.tree_size != null ? { tree_size: r.tree_size } : {}), ...(r.reason ? { reason: r.reason } : {}) }))
  });
  return results;
}

/**
 * The witness's HTTP side, the same for the Worker and the Node runner: it
 * serves what the witness has already stored and nothing else. It never calls
 * a log, never runs a round and never writes, so no request from anyone can
 * make the witness reach out (docs/witness-network.md, failure mode 3).
 */
export async function serveRequest(request, { store, published }) {
  const headers = { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };
  const json = (status, body) => new Response(request.method === 'HEAD' ? null : JSON.stringify(body, null, 2) + '\n', { status, headers });
  if (request.method !== 'GET' && request.method !== 'HEAD') return json(405, { error: 'this witness only serves what it has stored; it accepts no writes' });
  const { pathname } = new URL(request.url);
  if (pathname === '/public-key.json') return published ? json(200, published) : json(503, { error: 'this witness has no key configured' });
  if (pathname === '/' || pathname === '/logs.json') {
    const logs = await store.get('logs.json');
    if (pathname === '/logs.json') return logs ? json(200, logs) : json(404, { error: 'no round has run yet' });
    return json(200, {
      format: 'riskrouter-witness|1',
      witness: published || null,
      last_round: logs || null,
      paths: ['/public-key.json', '/logs.json', '/cosignatures/<log>/latest.json', '/alarms/<log>.json'],
      about: 'An independent witness of append-only evidence logs. It co-signs a log\'s head only after checking it is consistent with every head it saw before. https://riskrouter.eu/witnesses'
    });
  }
  const m = pathname.match(/^\/(cosignatures\/([a-z0-9-]+)\/latest|alarms\/([a-z0-9-]+))\.json$/);
  if (m && LOG_ID.test(m[2] || m[3])) {
    const doc = await store.get(`${m[1]}.json`);
    return doc ? json(200, doc) : json(404, { error: m[2] ? 'no cosignature of that log' : 'no alarm for that log' });
  }
  return json(404, { error: 'not found' });
}
