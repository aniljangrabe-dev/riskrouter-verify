// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Anil Jangra
/**
 * What an OpenTimestamps proof currently attests, read from its bytes.
 *
 *   node tools/ots-status.mjs anchors/*.ots
 *
 * A proof fresh from a calendar carries a PendingAttestation: the calendar
 * undertook to include the digest. After `ots upgrade`, once Bitcoin has
 * confirmed, it also carries a BitcoinBlockHeaderAttestation. The two tags are
 * fixed by the format (python-opentimestamps, core/notary.py), so counting
 * them is enough to say which state a committed proof is in, with no network.
 *
 * tests/timestamp.test.mjs uses this to keep the site honest in both
 * directions: it may not call a proof confirmed while it is pending, and it
 * may not keep calling it pending once it is confirmed.
 */
import fs from 'node:fs';

const TAGS = {
  pending: Buffer.from('83dfe30d2ef90c8e', 'hex'),
  bitcoin: Buffer.from('0588960d73d71901', 'hex')
};

export function otsStatus(bytes) {
  const buffer = Buffer.from(bytes);
  const count = (tag) => {
    let n = 0;
    for (let i = buffer.indexOf(tag); i !== -1; i = buffer.indexOf(tag, i + 1)) n++;
    return n;
  };
  const pending = count(TAGS.pending);
  const bitcoin = count(TAGS.bitcoin);
  // A Bitcoin attestation's payload is varbytes holding one varuint: the block height.
  const blocks = [];
  for (let i = buffer.indexOf(TAGS.bitcoin); i !== -1; i = buffer.indexOf(TAGS.bitcoin, i + 1)) {
    let at = i + TAGS.bitcoin.length;
    const read = () => { let v = 0, shift = 0, x; do { x = buffer[at++]; v += (x & 0x7f) * 2 ** shift; shift += 7; } while (x & 0x80); return v; };
    read();                // payload length
    blocks.push(read());   // block height
  }
  return { pending, bitcoin, blocks, state: bitcoin > 0 ? 'bitcoin' : pending > 0 ? 'pending' : 'unknown' };
}

if (process.argv[1] && process.argv[1].endsWith('ots-status.mjs')) {
  for (const file of process.argv.slice(2)) {
    const s = otsStatus(fs.readFileSync(file));
    console.log(`${s.state.padEnd(8)} ${file}  (pending ${s.pending}, bitcoin ${s.bitcoin}${s.blocks.length ? ', block ' + s.blocks.join(', ') : ''})`);
  }
}
