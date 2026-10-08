#!/usr/bin/env node
/**
 * Was it reported in time? Deadline proofs from sealed reports.
 * docs/deadline-proofs.md.
 *
 *   node deadline.mjs check report-bundle.json [more bundles...] [--key <key file or directory>]
 *
 * Each argument is a record bundle (riskrouter-record-bundle|1) of a report a
 * firm sent: a NIS2 or GDPR notification (pack nis2, kind
 * security.notification) or a Cyber Resilience Act report (pack cra, kind
 * cra.vulnerability-report). For each, this checks the bundle as any verifier
 * does (record, salt, proof, head signature), then the deadline:
 *
 *   NIS2 Article 23(4)      early warning 24 h and incident notification 72 h from aware_at;
 *                           final report one month after the incident notification
 *   GDPR Article 33(1)      breach notification 72 h from aware_at ("where feasible")
 *   CRA Article 14(2)       early warning 24 h and vulnerability notification 72 h from aware_at;
 *                           final report 14 days after corrective_measure_at
 *
 * against two times: submitted_at, the time the firm says it sent the report,
 * and created_at of the leaf, the time the log sealed the record of it, which
 * the firm did not choose. A report sealed before its deadline was, at the
 * latest, recorded as sent by then. aware_at is the firm's own statement; the
 * earliest sealed record of the incident bounds it from above, and this tool
 * says so when it is given one (any bundle of the same incident or
 * vulnerability that is not a report).
 *
 * What it does not decide: whether an incident was significant, whether a
 * report was needed, or whether its content was adequate. Standard-library Node.
 */
import fs from 'node:fs';

const HOUR = 3600e3;
const addMonth = (iso) => { const d = new Date(iso); d.setUTCMonth(d.getUTCMonth() + 1); return d; };
const t = (s) => new Date(s).getTime();
const fmt = (ms) => new Date(ms).toISOString().replace('.000Z', 'Z');
const span = (ms) => {
  const h = Math.floor(Math.abs(ms) / HOUR);
  const m = Math.round((Math.abs(ms) % HOUR) / 60e3);
  return `${h} h ${String(m).padStart(2, '0')} min`;
};

/** The deadline a report is held to, or null when this tool does not compute one. */
export function deadlineOf(record, all = []) {
  const { kind, stage, aware_at } = record;
  if (kind === 'security.notification') {
    if (stage === 'early-warning') return { due: t(aware_at) + 24 * HOUR, rule: 'NIS2 Article 23(4): early warning within 24 hours of becoming aware' };
    if (stage === 'incident-notification') return { due: t(aware_at) + 72 * HOUR, rule: 'NIS2 Article 23(4): incident notification within 72 hours of becoming aware' };
    if (stage === 'breach-notification') return { due: t(aware_at) + 72 * HOUR, rule: 'GDPR Article 33(1): breach notification within 72 hours of becoming aware, where feasible' };
    if (stage === 'final-report') {
      const n = all.find((r) => r.kind === 'security.notification' && r.stage === 'incident-notification' && r.incident_ref === record.incident_ref);
      return n ? { due: addMonth(n.submitted_at).getTime(), rule: 'NIS2 Article 23(4): final report within one month of the incident notification' }
        : { missing: 'the final report runs from the incident notification: include its bundle' };
    }
    return null;
  }
  if (kind === 'cra.vulnerability-report') {
    if (stage === 'early-warning') return { due: t(aware_at) + 24 * HOUR, rule: 'CRA Article 14(2): early warning within 24 hours of becoming aware' };
    if (stage === 'vulnerability-notification') return { due: t(aware_at) + 72 * HOUR, rule: 'CRA Article 14(2): vulnerability notification within 72 hours of becoming aware' };
    if (stage === 'final-report') {
      return record.corrective_measure_at ? { due: t(record.corrective_measure_at) + 14 * 24 * HOUR, rule: 'CRA Article 14(2): final report within 14 days of a corrective or mitigating measure' }
        : { missing: 'the final report runs from corrective_measure_at, which the record does not carry' };
    }
  }
  return null;
}

/** Lines of { ok | failed | skipped } for a set of bundles. */
export async function checkDeadlines(bundles, ring) {
  const { checkArtefact } = await import('./conformance.mjs');
  const lines = [];
  const records = bundles.map((b) => b?.record || {});
  for (const [i, b] of bundles.entries()) {
    const r = b?.record || {};
    const name = `${r.record_id || `bundle ${i + 1}`}`;
    const integrity = await checkArtefact(b, ring);
    for (const l of integrity) { const [k, v] = Object.entries(l)[0]; lines.push({ [k]: `${name}: ${v}` }); }
    if (integrity.some((l) => l.failed)) { lines.push({ failed: `${name}: not checked against a deadline, because the bundle does not verify` }); continue; }
    const d = deadlineOf(r, records);
    if (!d) { lines.push({ skipped: `${name}: ${r.kind} ${r.stage ?? ''} has no deadline this tool computes` }); continue; }
    if (d.missing) { lines.push({ failed: `${name}: ${d.missing}` }); continue; }
    const sealed = t(b.proof.entry.created_at);
    const submitted = t(r.submitted_at);
    lines.push({ ok: `${name}: ${d.rule}; due ${fmt(d.due)}` });
    lines.push(submitted <= d.due ? { ok: `${name}: sent ${fmt(submitted)} by the firm's own record, ${span(d.due - submitted)} before the deadline` }
      : { failed: `${name}: sent ${fmt(submitted)} by the firm's own record, ${span(submitted - d.due)} after the deadline${r.delay_reason ? ' (a reason for the delay is recorded)' : ''}` });
    lines.push(sealed <= d.due ? { ok: `${name}: sealed by the log at ${fmt(sealed)}, before the deadline: the record of sending existed by then` }
      : { failed: `${name}: sealed by the log at ${fmt(sealed)}, after the deadline: the log cannot confirm the report was recorded in time` });
    if (submitted > sealed) lines.push({ failed: `${name}: says it was sent at ${fmt(submitted)}, after the log sealed it at ${fmt(sealed)}` });
    // The earliest sealed record of the same incident or vulnerability bounds aware_at from above.
    const ref = r.incident_ref ?? r.vulnerability_ref;
    const earliest = bundles
      .filter((x) => (x?.record?.incident_ref ?? x?.record?.vulnerability_ref) === ref && x?.proof?.entry?.created_at)
      .map((x) => t(x.proof.entry.created_at)).sort((a, z) => a - z)[0];
    if (earliest !== undefined && t(r.aware_at) > earliest) {
      lines.push({ failed: `${name}: says the firm became aware at ${r.aware_at}, after it had already sealed a record of the same matter at ${fmt(earliest)}` });
    } else if (earliest !== undefined) {
      lines.push({ ok: `${name}: aware_at ${r.aware_at} is the firm's statement; the earliest sealed record of this matter is from ${fmt(earliest)}, which it does not contradict` });
    }
  }
  return lines;
}

/* -------------------------------------------------------------------- cli */

if (process.argv[1] && process.argv[1].endsWith('deadline.mjs')) {
  const args = process.argv.slice(2);
  const ki = args.indexOf('--key');
  const key = ki >= 0 ? args[ki + 1] : null;
  const files = args.filter((a, i) => i > 0 && a !== '--key' && (ki < 0 || i !== ki + 1));
  if (args[0] !== 'check' || !files.length) {
    console.error('usage: node deadline.mjs check <report-bundle.json>... [--key <file|dir>]');
    process.exit(2);
  }
  const { loadKeyring } = await import('./keyring.mjs');
  const lines = await checkDeadlines(files.map((f) => JSON.parse(fs.readFileSync(f, 'utf8'))), key ? loadKeyring(key) : null);
  for (const l of lines) console.log(l.ok ? `OK    ${l.ok}` : l.failed ? `FAIL  ${l.failed}` : `SKIP  ${l.skipped}`);
  process.exit(lines.some((l) => l.failed) ? 1 : 0);
}
