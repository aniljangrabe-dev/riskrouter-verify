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
    if (expected !== result.head_hash) {
      console.error('\nMISMATCH against the head you recorded earlier.');
      console.error(`  expected ${expected}`);
      console.error(`  computed ${result.head_hash}`);
      console.error('History has been altered, or you are looking at a different ledger.');
      process.exit(1);
    }
    console.log('MATCHES the head hash you recorded earlier. History is unchanged.');
  }
}
