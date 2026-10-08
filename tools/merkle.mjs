/**
 * The v2 evidence log's Merkle tree: RFC 6962 / RFC 9162 (Certificate
 * Transparency), unchanged, so any existing CT tooling can check it.
 *
 *   leaf hash  = SHA-256(0x00 || leaf bytes)        (computed by the database)
 *   node hash  = SHA-256(0x01 || left || right)
 *   empty tree = SHA-256("")
 *
 * Shared by worker.js (which serves heads and proofs) and the verifiers, so
 * the tree the Worker commits to and the tree a holder checks are the same
 * code. WebCrypto only, so it runs unchanged in a Worker, in Node and in a
 * browser. Everything takes and returns lowercase hex.
 *
 * Why a tree, when v1 is a chain: a chain proves an entry only to someone who
 * can recompute every entry after it, so the links through other
 * distributors' entries are the operator's word. A tree proves one entry
 * against the signed head with log2(n) hashes, and proves any earlier head is
 * a prefix of a later one, which is what an independent witness checks.
 */

const hex = (bytes) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
const unhex = (h) => Uint8Array.from(h.match(/../g) || [], (b) => parseInt(b, 16));
const HEX64 = /^[0-9a-f]{64}$/;

async function sha256(bytes) {
  return hex(await crypto.subtle.digest('SHA-256', bytes));
}

export async function leafHash(leafBytes) {
  const data = new Uint8Array(leafBytes.length + 1);
  data[0] = 0x00;
  data.set(leafBytes, 1);
  return sha256(data);
}

export async function nodeHash(left, right) {
  const data = new Uint8Array(65);
  data[0] = 0x01;
  data.set(unhex(left), 1);
  data.set(unhex(right), 33);
  return sha256(data);
}

export const EMPTY_ROOT = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

/** Largest power of two strictly less than n (n >= 2). */
function split(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** MTH(D[n]) over leaf hashes. */
export async function rootHash(leaves) {
  if (leaves.length === 0) return EMPTY_ROOT;
  if (leaves.length === 1) return leaves[0];
  const k = split(leaves.length);
  return nodeHash(await rootHash(leaves.slice(0, k)), await rootHash(leaves.slice(k)));
}

/** PATH(m, D[n]): the audit path proving leaf m is in the tree of these leaves. */
export async function inclusionProof(index, leaves) {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) throw new RangeError('leaf index outside the tree');
  if (leaves.length === 1) return [];
  const k = split(leaves.length);
  return index < k
    ? [...await inclusionProof(index, leaves.slice(0, k)), await rootHash(leaves.slice(k))]
    : [...await inclusionProof(index - k, leaves.slice(k)), await rootHash(leaves.slice(0, k))];
}

/** PROOF(m, D[n]): proves the tree of the first m leaves is a prefix of the tree of all n. */
export async function consistencyProof(m, leaves) {
  const n = leaves.length;
  if (!Number.isInteger(m) || m < 1 || m > n) throw new RangeError('first tree size must be between 1 and the second');
  async function sub(size, part, whole) {
    if (size === part.length) return whole ? [] : [await rootHash(part)];
    const k = split(part.length);
    return size <= k
      ? [...await sub(size, part.slice(0, k), whole), await rootHash(part.slice(k))]
      : [...await sub(size - k, part.slice(k), false), await rootHash(part.slice(0, k))];
  }
  return sub(m, leaves, true);
}

/**
 * RFC 9162 §2.1.3.2. True only if `path` proves `leaf` sits at `index` in a
 * tree of `size` leaves whose root is `root`.
 */
export async function verifyInclusion(index, size, leaf, path, root) {
  if (!Number.isInteger(index) || !Number.isInteger(size) || index < 0 || index >= size) return false;
  if (!HEX64.test(leaf) || !HEX64.test(root) || !Array.isArray(path) || !path.every((p) => HEX64.test(p))) return false;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of path) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && r === root;
}

/**
 * RFC 9162 §2.1.4.2. True only if `path` proves the tree of `first` leaves
 * with root `firstRoot` is a prefix of the tree of `second` leaves with root
 * `secondRoot`. This is the check that catches a rebuilt history.
 */
export async function verifyConsistency(first, second, firstRoot, secondRoot, path) {
  if (!Number.isInteger(first) || !Number.isInteger(second) || first < 1 || first > second) return false;
  if (!HEX64.test(firstRoot) || !HEX64.test(secondRoot) || !Array.isArray(path) || !path.every((p) => HEX64.test(p))) return false;
  if (first === second) return path.length === 0 && firstRoot === secondRoot;
  let proof = path.slice();
  if ((first & (first - 1)) === 0) proof = [firstRoot, ...proof];   // first is a power of two
  if (proof.length === 0) return false;
  let fn = first - 1;
  let sn = second - 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  let fr = proof[0];
  let sr = proof[0];
  for (const c of proof.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
      }
    } else {
      sr = await nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && fr === firstRoot && sr === secondRoot;
}

/* ------------------------------------------------ leaf and head encodings */

/**
 * YYYY-MM-DDTHH:MM:SS.ffffffZ in UTC, the form the database writes into the
 * leaf string. PostgREST may read it back as "+00:00" with fewer fraction
 * digits; this puts it back. Same rule as canonicalTimestamp() in
 * tools/verify-ledger.mjs, so v1 and v2 agree on what a time looks like.
 */
export function canonicalTimestamp(value) {
  const match = String(value).match(
    /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(?:Z|([+-])(\d{2}):?(\d{2})?)?$/
  );
  if (!match) throw new Error(`unparseable timestamp: ${value}`);
  let [, y, mo, d, h, mi, s, frac = '', sign, oh, om = '00'] = match;
  if (sign) {
    const offset = (Number(oh) * 60 + Number(om)) * (sign === '-' ? -1 : 1);
    if (offset !== 0) {
      const utc = new Date(Date.UTC(+y, +mo - 1, +d, +h, +mi, +s) - offset * 60000);
      y = String(utc.getUTCFullYear()).padStart(4, '0');
      mo = String(utc.getUTCMonth() + 1).padStart(2, '0');
      d = String(utc.getUTCDate()).padStart(2, '0');
      h = String(utc.getUTCHours()).padStart(2, '0');
      mi = String(utc.getUTCMinutes()).padStart(2, '0');
      s = String(utc.getUTCSeconds()).padStart(2, '0');
    }
  }
  return `${y}-${mo}-${d}T${h}:${mi}:${s}.${frac.padEnd(6, '0')}Z`;
}

/**
 * Frozen, like v1's canonical form: changing it changes every leaf hash.
 * v2 is the unsigned leaf. v3 (docs/signed-leaves.md) adds the client's own
 * signature over its claim, inside the leaf; an entry says which it is with
 * leaf_version, or by carrying signer_key_id. Both live in the same tree.
 */
export function leafString(entry) {
  const { leaf_index, created_at, distributor_id, kind, record_digest } = entry;
  if (Number(entry.leaf_version) === 3 || entry.signer_key_id) {
    return ['riskrouter-evidence-leaf', 'v3', String(leaf_index), created_at, distributor_id, kind, record_digest,
      entry.signer_key_id, entry.claimed_at, entry.client_signature].join('|');
  }
  return ['riskrouter-evidence-leaf', 'v2', String(leaf_index), created_at, distributor_id, kind, record_digest].join('|');
}

/** Frozen: what the client signs, before the log assigns anything. */
export function claimPayload({ kind, record_digest, signer_key_id, claimed_at }) {
  return ['riskrouter-evidence-claim', 'v3', kind, record_digest, signer_key_id, claimed_at].join('|');
}

/** A signer's key id, derived as a witness id is: SHA-256 over the JWK's x and y, first 16 hex. */
export async function signerKeyId(jwk) {
  return (await sha256(new TextEncoder().encode(JSON.stringify([jwk.x, jwk.y])))).slice(0, 16);
}

/** True only if the client's signature over the claim payload verifies with this JWK. */
export async function verifyClaim(entry, jwk) {
  try {
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256') return false;
    const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const signature = Uint8Array.from(atob(String(entry.client_signature || '')), (c) => c.charCodeAt(0));
    if (signature.length !== 64) return false;
    return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, new TextEncoder().encode(claimPayload(entry)));
  } catch {
    return false;
  }
}

/** Frozen, like v1's attestation payload: changing it invalidates every saved head. */
export function headPayload({ tree_size, root_hash, timestamp }) {
  return ['riskrouter-evidence-head', 'v2', String(tree_size), root_hash, timestamp].join('|');
}

/* ------------------------------------------------- completeness chains */

/**
 * docs/completeness.md, settled 7 October 2026 with the repository owner's
 * decision. A firm puts records in numbered chains: each record carries
 * chain_tag, chain_seq and chain_prev (the previous record's digest) inside
 * itself, and sends chain_tag and chain_seq beside its digest. The log
 * refuses a number out of turn or a tag another distributor owns, and signs a
 * statement of the chain as of a signed head, so a record left out is a gap.
 *
 *   link line      chain_seq|leaf_index|created_at|record_digest\n
 *   links_digest   SHA-256(UTF-8(the link lines from `from` to `to`, concatenated))
 *   chain payload  riskrouter-evidence-chain|v1|chain_tag|length|tree_size|root_hash|timestamp|from|to|links_digest
 *
 * Frozen, like the head payload: changing them invalidates every statement saved.
 */
export const CHAIN_FORMAT = 'riskrouter-evidence-chain|v1';
export const CHAIN_GENESIS = '0'.repeat(64);

export function chainLine({ chain_seq, leaf_index, created_at, record_digest }) {
  return `${chain_seq}|${leaf_index}|${created_at}|${record_digest}\n`;
}

export async function linksDigest(links) {
  return sha256(new TextEncoder().encode(links.map(chainLine).join('')));
}

export function chainPayload({ chain_tag, length, head, from, to, links_digest }) {
  return ['riskrouter-evidence-chain', 'v1', chain_tag, String(length), String(head.tree_size), head.root_hash, head.timestamp,
    String(from), String(to), links_digest].join('|');
}

/* ------------------------------------------- the tree from stored nodes */

/**
 * The same tree, read from stored subtree roots instead of every leaf.
 *
 * docs/scale-design.md §2: the database keeps `evidence_nodes (level,
 * node_index, hash)`, where node (L, i) is the root of leaves
 * [i·2^L, (i+1)·2^L), written the moment that subtree completes. Any range
 * RFC 9162's split rule produces is either a complete aligned subtree (one
 * stored node) or splits into one plus a smaller ragged remainder, so a root
 * or a proof needs O(log n) nodes rather than n leaves.
 *
 * `get(level, index)` returns a node's hash. These functions are written to
 * give exactly the answers rootHash / inclusionProof / consistencyProof give
 * over the leaves; tests/merkle.test.mjs holds them equal for every size up
 * to 300, and the schema test holds the database's own fold to the same.
 */

/** The parent nodes that appending leaf `index` completes, lowest level first. */
export function completedNodes(index) {
  const nodes = [];
  for (let level = 1, span = 2; (index + 1) % span === 0; level++, span *= 2) {
    nodes.push({ level, index: (index + 1) / span - 1 });
  }
  return nodes;
}

/** MTH over leaves [start, start + len), from stored nodes. */
async function mthFromNodes(start, len, get) {
  if (len === 1) return get(0, start);
  let level = 0;
  let span = 1;
  while (span * 2 <= len) { span *= 2; level++; }
  if (span === len && start % len === 0) return get(level, start / len);
  const k = split(len);
  return nodeHash(await mthFromNodes(start, k, get), await mthFromNodes(start + k, len - k, get));
}

export async function rootFromNodes(size, get) {
  if (!Number.isInteger(size) || size < 0) throw new RangeError('tree size must be a whole number');
  return size === 0 ? EMPTY_ROOT : mthFromNodes(0, size, get);
}

export async function inclusionFromNodes(index, size, get) {
  if (!Number.isInteger(index) || index < 0 || index >= size) throw new RangeError('leaf index outside the tree');
  async function path(m, start, len) {
    if (len === 1) return [];
    const k = split(len);
    return m < k
      ? [...await path(m, start, k), await mthFromNodes(start + k, len - k, get)]
      : [...await path(m - k, start + k, len - k), await mthFromNodes(start, k, get)];
  }
  return path(index, 0, size);
}

export async function consistencyFromNodes(m, size, get) {
  if (!Number.isInteger(m) || m < 1 || m > size) throw new RangeError('first tree size must be between 1 and the second');
  async function sub(first, start, len, whole) {
    if (first === len) return whole ? [] : [await mthFromNodes(start, len, get)];
    const k = split(len);
    return first <= k
      ? [...await sub(first, start, k, whole), await mthFromNodes(start + k, len - k, get)]
      : [...await sub(first - k, start + k, len - k, false), await mthFromNodes(start, k, get)];
  }
  return sub(m, 0, size, true);
}

/**
 * Which nodes a computation will ask for, found by running it once with a
 * getter that records and answers with a placeholder. The control flow of
 * every function above depends only on sizes and indexes, never on a hash
 * value, so the plan is exact. A caller fetches the whole plan in one query
 * and runs the computation a second time against the answers.
 */
export async function planNodes(run) {
  const keys = [];
  const seen = new Set();
  await run(async (level, index) => {
    const key = `${level}:${index}`;
    if (!seen.has(key)) { seen.add(key); keys.push({ level, index }); }
    return '0'.repeat(64);
  });
  return keys;
}
