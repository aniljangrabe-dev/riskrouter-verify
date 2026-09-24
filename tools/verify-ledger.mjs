#!/usr/bin/env node
/**
 * Independent verifier for the RiskRouter audit chain.
 *
 * This is the point of the whole exercise: it shares no code with the database.
 * It rebuilds every digest from the published canonical form using nothing but
 * Node's standard library, so agreement between the two is evidence rather than
 * a tautology. If they ever disagree, one of them is wrong and you should not
 * trust either until you know which.
 *
 * The canonical form is frozen: once a distributor records a head hash,
 * changing it would destroy their proof. Never edit the field list below
 * without re-chaining the whole ledger, which is only acceptable while no head
 * hash has been published.
 *
 * A distributor or a regulator can run this without asking us for anything
 * beyond the rows, and can compare the head hash against one they recorded
 * earlier. An operator who quietly edits history cannot make both match.
 *
 *   node tools/verify-ledger.mjs rows.json
 *   node tools/verify-ledger.mjs rows.json --expect-head <hash recorded earlier>
 *     (the recorded head may be this file's head or any earlier one in its chain)
 *
 * It reads two shapes:
 *
 *   rows.json     a plain array of entries, for whoever holds the database.
 *   export.json   what GET /api/v1/ledger/export returns to a distributor.
 *
 * The export shape exists because the first one asked for a Supabase
 * credential that a distributor will never hold. A verification you cannot run
 * without the operator handing you their keys is not a verification. An export
 * carries the caller's own entries in full, plus (chain_index, row_hash,
 * prev_hash) for every entry in the ledger, which is enough to rebuild each of
 * your own digests from content and then follow the links to the signed head.
 *
 *   curl -H "Authorization: Bearer $RISKROUTER_API_KEY" \
 *     https://api.riskrouter.eu/api/v1/ledger/export > export.json
 *   node tools/verify-attestation.mjs export.json
 *   node tools/verify-ledger.mjs export.json
 */
import fs from 'node:fs';
import crypto from 'node:crypto';

const GENESIS = '0'.repeat(64);

/** Postgres renders timestamps as YYYY-MM-DDTHH:MM:SS.ffffffZ in UTC. */
function canonicalTimestamp(value) {
  const match = String(value).match(
    /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(?:Z|([+-])(\d{2}):?(\d{2})?)?$/
  );
  if (!match) throw new Error(`unparseable timestamp: ${value}`);
  let [, y, mo, d, h, mi, s, frac = '', sign, oh, om = '00'] = match;

  if (sign) {
    // Shift to UTC. Postgres stores UTC; an offset in the export is presentation.
    const offset = (Number(oh) * 60 + Number(om)) * (sign === '-' ? -1 : 1);
    if (offset !== 0) {
      const at = Date.UTC(+y, +mo - 1, +d, +h, +mi, +s) - offset * 60_000;
      const utc = new Date(at);
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

/** Components sorted by key, joined as key=true|false. No quoting, no spacing. */
function canonicalComponents(components) {
  return Object.keys(components || {}).sort()
    .map((k) => `${k}=${components[k] === true ? 'true' : 'false'}`)
    .join(',');
}

/** numeric(10,2) always renders with exactly two decimals. */
function canonicalPremium(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) throw new Error(`unparseable premium: ${value}`);
  return n.toFixed(2);
}

export function canonicalForm(row, prevHash) {
  return [
    String(row.chain_index),
    row.id,
    canonicalTimestamp(row.created_at),
    row.active_vertical,
    canonicalComponents(row.selected_components),
    canonicalPremium(row.total_monthly_premium),
    row.compliance_status,
    row.matrix_version ?? '',
    row.distributor_id ?? '',
    prevHash
  ].join('|');
}

export function verify(rows) {
  const ordered = [...rows].sort((a, b) => Number(a.chain_index) - Number(b.chain_index));
  let prev = GENESIS;

  for (let i = 0; i < ordered.length; i++) {
    const row = ordered[i];
    const expectedIndex = i + 1;

    if (Number(row.chain_index) !== expectedIndex) {
      return { intact: false, checked: i, broken_at: row.chain_index, reason: 'chain index is not contiguous, an entry is missing or duplicated' };
    }
    if (row.prev_hash !== prev) {
      return { intact: false, checked: i, broken_at: row.chain_index, reason: 'previous hash does not match the entry before it' };
    }

    const digest = crypto.createHash('sha256').update(canonicalForm(row, prev)).digest('hex');
    if (digest !== row.row_hash) {
      return { intact: false, checked: i, broken_at: row.chain_index, reason: 'entry content does not match its own digest' };
    }
    prev = digest;
  }

  return { intact: true, checked: ordered.length, head_hash: prev };
}

/**
 * Verify an export: your own entries rebuilt from content, the whole chain
 * followed link by link, and the head compared to the one we signed.
 *
 * Be precise about what this establishes, because the tempting version is
 * wrong. Your entries are *proved*: their digests are recomputed from content
 * you can read. Everyone else's are only *followed* — the published digest is
 * taken as given and checked to link. So:
 *
 *   caught here    your own entry altered, because its content no longer
 *                  produces its published digest.
 *   caught here    a chain that does not link, or that does not reach the head
 *                  the operator signed.
 *   NOT caught     an operator who rewrites history and re-chains the whole
 *                  ledger. That forgery is internally consistent and will pass
 *                  every check in this file.
 *
 * The last one is why `--expect-head` exists and why exports are worth saving
 * on different dates. A re-chained ledger produces a different head, and a
 * head you recorded last month is a number the operator cannot go back and
 * change. One export proves consistency. A series of them proves history.
 */
export function verifyExport(doc) {
  const skeleton = [...(doc.skeleton || [])].sort((a, b) => Number(a.chain_index) - Number(b.chain_index));
  const mine = [...(doc.entries || [])].sort((a, b) => Number(a.chain_index) - Number(b.chain_index));

  if (skeleton.length === 0) {
    return { intact: false, reason: 'the export carries no chain skeleton, so nothing can be linked to the head' };
  }

  const prevByIndex = new Map();
  let prev = GENESIS;
  for (let i = 0; i < skeleton.length; i++) {
    const link = skeleton[i];
    const expectedIndex = i + 1;
    if (Number(link.chain_index) !== expectedIndex) {
      return { intact: false, checked: i, broken_at: link.chain_index, reason: 'chain index is not contiguous, an entry is missing or duplicated' };
    }
    if (link.prev_hash !== prev) {
      return { intact: false, checked: i, broken_at: link.chain_index, reason: 'previous hash does not match the entry before it' };
    }
    prevByIndex.set(Number(link.chain_index), prev);
    prev = link.row_hash;
  }
  const head = prev;

  // Now the half that is proof rather than assertion.
  let proved = 0;
  for (const row of mine) {
    const index = Number(row.chain_index);
    const link = skeleton[index - 1];
    if (!link) {
      return { intact: false, broken_at: index, reason: 'one of your entries is not present in the chain skeleton' };
    }
    const digest = crypto.createHash('sha256')
      .update(canonicalForm(row, prevByIndex.get(index))).digest('hex');
    if (digest !== link.row_hash) {
      return { intact: false, broken_at: index, reason: 'your entry content does not match the digest published for it' };
    }
    proved++;
  }

  const claimed = doc.attestation && doc.attestation.head_hash;
  if (claimed && claimed !== head) {
    return { intact: false, broken_at: skeleton.length, reason: `the chain produces ${head} but the signed attestation claims ${claimed}` };
  }

  return { intact: true, checked: skeleton.length, proved, head_hash: head, signed_head: claimed || null };
}

/* ------------------------------------------------------------ entry proof */

export const ENTRY_PROOF_FORMAT = 'riskrouter-entry-proof|v1';

/**
 * One entry, cut out of an export, for showing to someone who should see that
 * quote and no other: the entry in full, the links from it to the head, and
 * the signed attestation of that head.
 *
 * What it proves, precisely. The entry's content produces the digest the
 * ledger published for its position, and its own prev_hash is part of that
 * content. The links after it are the ledger's assertion, followed by digest
 * only, exactly as in an export. They become binding against a signed head:
 * anyone who later recomputes the full ledger must arrive at that head, and
 * cannot while this entry is altered or missing. The proof reveals nothing
 * about any other quote.
 */
/**
 * Where a head recorded earlier sits in this file's chain.
 *
 * A head is the digest of the last entry at the moment it was taken, so a
 * head saved last month is not today's head: it is an earlier link of today's
 * chain. Returns the chain_index of the entry whose digest it is (0 for the
 * empty ledger's head), or null when it is not in this chain at all: history
 * was altered, this is another ledger, or the head is newer than the file.
 * Only meaningful on a chain already verified intact.
 */
export function positionOfHead(doc, wanted) {
  const head = String(wanted || '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(head)) return null;
  if (head === GENESIS) return 0;
  const links = Array.isArray(doc) ? doc : (doc.skeleton || doc.rows || []);
  const hit = links.find((link) => link.row_hash === head);
  return hit ? Number(hit.chain_index) : null;
}

export function makeEntryProof(doc, which) {
  const entries = doc.entries || [];
  const entry = entries.find((e) => String(e.chain_index) === String(which) || e.id === which);
  if (!entry) throw new Error(`no entry ${which} among your ${entries.length} entries in this export`);
  const from = Number(entry.chain_index);
  const path = [...(doc.skeleton || [])]
    .sort((a, b) => Number(a.chain_index) - Number(b.chain_index))
    .filter((link) => Number(link.chain_index) >= from)
    .map(({ chain_index, row_hash, prev_hash }) => ({ chain_index, row_hash, prev_hash }));
  return {
    format: ENTRY_PROOF_FORMAT,
    note: 'One ledger entry and its links to a signed head. Check it at https://riskrouter.eu/verify or with node tools/verify-ledger.mjs.',
    entry,
    path,
    attestation: doc.attestation || null,
    ...(doc.signature ? { signature: doc.signature } : {})
  };
}

export function verifyEntryProof(doc) {
  const entry = doc.entry;
  const path = [...(doc.path || [])].sort((a, b) => Number(a.chain_index) - Number(b.chain_index));
  if (!entry || path.length === 0) return { intact: false, reason: 'the proof carries no entry or no path to the head' };

  const index = Number(entry.chain_index);
  if (Number(path[0].chain_index) !== index) {
    return { intact: false, broken_at: index, reason: 'the path does not start at this entry' };
  }
  for (let i = 1; i < path.length; i++) {
    if (Number(path[i].chain_index) !== index + i) {
      return { intact: false, broken_at: path[i].chain_index, reason: 'chain index is not contiguous, an entry is missing or duplicated' };
    }
    if (path[i].prev_hash !== path[i - 1].row_hash) {
      return { intact: false, broken_at: path[i].chain_index, reason: 'previous hash does not match the entry before it' };
    }
  }
  const digest = crypto.createHash('sha256').update(canonicalForm(entry, path[0].prev_hash)).digest('hex');
  if (digest !== path[0].row_hash) {
    return { intact: false, broken_at: index, reason: 'the entry content does not match the digest published for it' };
  }
  const head = path[path.length - 1].row_hash;
  const last = Number(path[path.length - 1].chain_index);
  const attestation = doc.attestation;
  if (!attestation || !attestation.head_hash) {
    return { intact: false, broken_at: last, reason: 'the proof carries no attestation, so it links to nothing anyone signed' };
  }
  if (attestation.head_hash !== head) {
    return { intact: false, broken_at: last, reason: `the path produces ${head} but the signed attestation claims ${attestation.head_hash}` };
  }
  if (Number(attestation.entries) !== last) {
    return { intact: false, broken_at: last, reason: `the path ends at entry ${last} but the attestation covers ${attestation.entries}` };
  }
  return { intact: true, index, links: path.length, head_hash: head };
}

/* ------------------------------------------------------------------ CLI */
const invokedDirectly = process.argv[1] && process.argv[1].endsWith('verify-ledger.mjs');
if (invokedDirectly) {
  const file = process.argv[2];
  if (!file) {
    console.error('usage: node tools/verify-ledger.mjs <rows.json> [--expect-head <hash>]');
    process.exit(2);
  }
  const expectIndex = process.argv.indexOf('--expect-head');
  const expected = expectIndex > -1 ? process.argv[expectIndex + 1] : null;

  const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  const isExport = !Array.isArray(parsed) && typeof parsed.format === 'string'
    && parsed.format.startsWith('riskrouter-ledger-export|');

  if (!Array.isArray(parsed) && parsed.format === ENTRY_PROOF_FORMAT) {
    const proof = verifyEntryProof(parsed);
    if (!proof.intact) {
      console.error(`BROKEN  entry proof fails at ${proof.broken_at ?? '?'}`);
      console.error(`        ${proof.reason}`);
      process.exit(1);
    }
    console.log(`PROVED  entry ${proof.index} is rebuilt from its own content and matches its published digest`);
    console.log(`LINKED  ${proof.links} links to the head, followed by digest only`);
    console.log(`HEAD    ${proof.head_hash}, as the attestation in this file claims`);
    console.log('        Check the signature with: node tools/verify-attestation.mjs <this file>');
    process.exit(0);
  }

  const result = isExport
    ? verifyExport(parsed)
    : verify(Array.isArray(parsed) ? parsed : parsed.rows || []);

  if (!result.intact) {
    console.error(`BROKEN  ${result.checked ?? 0} entries verified, then entry ${result.broken_at} failed`);
    console.error(`        ${result.reason}`);
    process.exit(1);
  }

  console.log(`INTACT  ${result.checked} entries`);
  if (isExport) {
    console.log(`PROVED  ${result.proved} of them are yours, rebuilt from their own content`);
    console.log(result.signed_head
      ? '        the rest are followed by digest only, which is what catches a change to them'
      : '        this export carries no attestation, so nothing here is signed');
  }
  console.log(`HEAD    ${result.head_hash}`);

  if (expected) {
    const at = positionOfHead(isExport ? parsed : (Array.isArray(parsed) ? parsed : parsed.rows || []), expected);
    if (at === null) {
      console.error('\nMISMATCH against the head you recorded earlier: it is not a head of this chain.');
      console.error(`  expected ${expected}`);
      console.error(`  this file's head ${result.head_hash}`);
      console.error('History has been altered, you are looking at a different ledger, or the head is newer than this file.');
      process.exit(1);
    }
    const added = result.checked - at;
    console.log(added === 0
      ? 'MATCHES the head hash you recorded earlier. History is unchanged.'
      : `MATCHES the head hash you recorded earlier: it was the head after entry ${at}. History up to that entry is unchanged; ${added} ${added === 1 ? 'entry has' : 'entries have'} been added since.`);
  }
}
