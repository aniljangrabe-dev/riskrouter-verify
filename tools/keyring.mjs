/**
 * Every signing key we have ever published, chosen by the key id a signature names.
 *
 * Rule 9 keeps each public key in anchors/ for ever, so an attestation signed
 * before a rotation stays checkable after it. A verifier that only ever read
 * anchors/signing-key.json would pass that promise in the letter and break it
 * in practice: after the first rotation, every attestation saved before it
 * would fail by default. So verifiers read the whole keyring and pick the key
 * the signature says it was made with.
 *
 * The keyring is every anchors/signing-key*.json. The current key is
 * signing-key.json; a retired one keeps its file as signing-key-<key_id>.json
 * (docs/runbooks/signing-key-rotation.md).
 *
 * Picking by key id is not a trust decision: the id only says which of OUR
 * published keys to try. A signature still has to verify against that key.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ANCHORS = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'anchors');

const KEY_FILE = /^signing-key(-[0-9a-z]+)?\.json$/i;

/** A file holds one key; a directory holds the keyring. */
export function loadKeyring(location = ANCHORS) {
  const stat = fs.statSync(location);
  const files = stat.isDirectory()
    ? fs.readdirSync(location).filter((f) => KEY_FILE.test(f)).sort().map((f) => path.join(location, f))
    : [location];
  const ring = files.map((f) => JSON.parse(fs.readFileSync(f, 'utf8')));
  const ids = new Set();
  for (const k of ring) {
    if (!k || !k.public_key) throw new Error('a keyring entry has no public_key');
    if (k.key_id && ids.has(k.key_id)) throw new Error(`key id ${k.key_id} appears twice in the keyring`);
    if (k.key_id) ids.add(k.key_id);
  }
  return ring;
}

/**
 * The key a signature names. A ring of one unnamed key is used as given, the
 * way a holder with a single key file expects; otherwise the id must match.
 */
export function pickKey(ring, keyId) {
  const keys = Array.isArray(ring) ? ring : [ring];
  if (keyId) {
    const found = keys.find((k) => k.key_id === keyId);
    if (found) return found;
    if (keys.length === 1 && !keys[0].key_id) return keys[0];
    return null;
  }
  return keys.length === 1 ? keys[0] : null;
}
