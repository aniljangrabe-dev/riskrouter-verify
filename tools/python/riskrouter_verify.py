#!/usr/bin/env python3
"""
riskrouter_verify.py: an independent verifier for RiskRouter evidence.

    python3 riskrouter_verify.py FILE [--key signing-key.json | --key anchors/] [--expect-head HEX]
                                      [--saved-head HEAD.json] [--witness-key KEY.json]
    python3 riskrouter_verify.py --self-test

Standard library only. Python 3.8 or later. No network access, ever.

It shares no code with the service it checks, and none with the JavaScript
verifier either: the canonical forms, the Merkle tree and ECDSA P-256 are
reimplemented here from the specification at https://riskrouter.eu/spec. Two
implementations that agree, written separately, are worth more than one that
agrees with itself; the repository's tests hold them to identical verdicts.

FILE may be any of:
    a v1 ledger export              riskrouter-ledger-export|v1
    a v1 single-entry proof         riskrouter-entry-proof|v1
    a v1 saved attestation          {"attestation": ..., "signature": ...}
    a v2 evidence proof             riskrouter-evidence-proof|v2         (a v3 signed leaf too; --signer-key optional)
    a v2 consistency proof          riskrouter-evidence-consistency|v2  (needs --saved-head)
    a v2 witness cosignature        riskrouter-evidence-cosignature|v2   (needs --witness-key)
    a record bundle                 riskrouter-record-bundle|1           (a record, its salt, and its evidence proof)
    a selective disclosure          riskrouter-disclosure-bundle|1       (some fields of a sealed record, the rest still sealed)
    a chain statement               riskrouter-evidence-chain|v1         (what the log holds in one completeness chain)
    a completeness bundle           riskrouter-completeness-bundle|1     (every record of a chain: none left out)
    a spot-check bundle             riskrouter-spot-check-bundle|1       (the records a Bitcoin block hash selected)
    a co-sealed record              riskrouter-coseal|1                  (the same record, signed by two parties)
    an RFC 3161 head timestamp      riskrouter-head-timestamp|1          (--key checks our signature on the head too)
    a list of v1 ledger rows
    a C2SP checkpoint (signed note)  c2sp.org/tlog-checkpoint           (needs --vkey; --witness-vkey, repeatable)
    a SCITT COSE Receipt, or a Transparent Statement carrying ours (binary; needs --key; --statement optional)

Exit status: 0 verified, 1 not verified, 2 usage.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal

GENESIS = "0" * 64
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------- ECDSA P-256
# FIPS 186-4 / SEC 2 curve secp256r1. Verification only.

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _on_curve(pt):
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _mul(k, pt):
    result = None
    addend = pt
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def _b64url(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def ecdsa_p256_verify(jwk, message, signature_b64):
    """True only if signature_b64 (raw r||s, base64) signs message under the JWK public key."""
    try:
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            return False
        q = (int.from_bytes(_b64url(jwk["x"]), "big"), int.from_bytes(_b64url(jwk["y"]), "big"))
        if not _on_curve(q):
            return False
        raw = base64.b64decode(signature_b64, validate=True)
        if len(raw) != 64:
            return False
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
        if not (1 <= r < N and 1 <= s < N):
            return False
        e = int.from_bytes(hashlib.sha256(message).digest(), "big")
        w = pow(s, -1, N)
        point = _add(_mul(e * w % N, G), _mul(r * w % N, q))
        return point is not None and point[0] % N == r
    except Exception:
        return False


# -------------------------------------------------------------- v1 ledger

_TS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(?:Z|([+-])(\d{2}):?(\d{2})?)?$")


def canonical_timestamp(value):
    m = _TS.match(str(value))
    if not m:
        raise ValueError("unparseable timestamp: %s" % value)
    y, mo, d, h, mi, s, frac, sign, oh, om = m.groups()
    frac = frac or ""
    if sign:
        offset = (int(oh) * 60 + int(om or "00")) * (-1 if sign == "-" else 1)
        if offset:
            t = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), tzinfo=timezone.utc) - timedelta(minutes=offset)
            y, mo, d, h, mi, s = ("%04d" % t.year, "%02d" % t.month, "%02d" % t.day,
                                  "%02d" % t.hour, "%02d" % t.minute, "%02d" % t.second)
    return "%s-%s-%sT%s:%s:%s.%sZ" % (y, mo, d, h, mi, s, frac.ljust(6, "0"))


def _canonical_components(components):
    return ",".join("%s=%s" % (k, "true" if components[k] is True else "false") for k in sorted(components or {}))


def _canonical_premium(value):
    return "%.2f" % Decimal(str(value))


def canonical_form(row, prev_hash):
    return "|".join([
        str(row["chain_index"]), row["id"], canonical_timestamp(row["created_at"]), row["active_vertical"],
        _canonical_components(row.get("selected_components")), _canonical_premium(row["total_monthly_premium"]),
        row["compliance_status"], row.get("matrix_version") or "", row.get("distributor_id") or "", prev_hash,
    ])


def _entry_digest(row, prev_hash):
    return sha256_hex(canonical_form(row, prev_hash).encode("utf-8"))


def verify_rows(rows):
    ordered = sorted(rows, key=lambda r: int(r["chain_index"]))
    prev = GENESIS
    for i, row in enumerate(ordered):
        if int(row["chain_index"]) != i + 1:
            return {"intact": False, "checked": i, "broken_at": row["chain_index"],
                    "reason": "chain index is not contiguous, an entry is missing or duplicated"}
        if row.get("prev_hash") != prev:
            return {"intact": False, "checked": i, "broken_at": row["chain_index"],
                    "reason": "previous hash does not match the entry before it"}
        digest = _entry_digest(row, prev)
        if digest != row.get("row_hash"):
            return {"intact": False, "checked": i, "broken_at": row["chain_index"],
                    "reason": "entry content does not match its own digest"}
        prev = digest
    return {"intact": True, "checked": len(ordered), "head_hash": prev}


def position_of_head(doc, wanted):
    """Where a head recorded earlier sits in this file's chain.

    A head saved last month is an earlier link of today's chain, not today's
    head. Returns the chain_index of the entry whose digest it is (0 for the
    empty ledger's head), or None when it is not in this chain at all. Only
    meaningful on a chain already verified intact."""
    head = str(wanted or "").strip().lower()
    if len(head) != 64 or any(c not in "0123456789abcdef" for c in head):
        return None
    if head == GENESIS:
        return 0
    links = doc if isinstance(doc, list) else (doc.get("skeleton") or doc.get("rows") or [])
    for link in links:
        if link.get("row_hash") == head:
            return int(link["chain_index"])
    return None


def verify_export(doc):
    skeleton = sorted(doc.get("skeleton") or [], key=lambda r: int(r["chain_index"]))
    mine = sorted(doc.get("entries") or [], key=lambda r: int(r["chain_index"]))
    if not skeleton:
        return {"intact": False, "reason": "the export carries no chain skeleton, so nothing can be linked to the head"}
    prev_by_index = {}
    prev = GENESIS
    for i, link in enumerate(skeleton):
        if int(link["chain_index"]) != i + 1:
            return {"intact": False, "checked": i, "broken_at": link["chain_index"],
                    "reason": "chain index is not contiguous, an entry is missing or duplicated"}
        if link.get("prev_hash") != prev:
            return {"intact": False, "checked": i, "broken_at": link["chain_index"],
                    "reason": "previous hash does not match the entry before it"}
        prev_by_index[int(link["chain_index"])] = prev
        prev = link["row_hash"]
    head = prev
    proved = 0
    for row in mine:
        index = int(row["chain_index"])
        if index < 1 or index > len(skeleton):
            return {"intact": False, "broken_at": index, "reason": "one of your entries is not present in the chain skeleton"}
        if _entry_digest(row, prev_by_index[index]) != skeleton[index - 1]["row_hash"]:
            return {"intact": False, "broken_at": index, "reason": "your entry content does not match the digest published for it"}
        proved += 1
    claimed = (doc.get("attestation") or {}).get("head_hash")
    if claimed and claimed != head:
        return {"intact": False, "broken_at": len(skeleton),
                "reason": "the chain produces %s but the signed attestation claims %s" % (head, claimed)}
    return {"intact": True, "checked": len(skeleton), "proved": proved, "head_hash": head, "signed_head": claimed or None}


def verify_entry_proof(doc):
    entry = doc.get("entry")
    path = sorted(doc.get("path") or [], key=lambda r: int(r["chain_index"]))
    if not entry or not path:
        return {"intact": False, "reason": "the proof carries no entry or no path to the head"}
    index = int(entry["chain_index"])
    if int(path[0]["chain_index"]) != index:
        return {"intact": False, "broken_at": index, "reason": "the path does not start at this entry"}
    for i in range(1, len(path)):
        if int(path[i]["chain_index"]) != index + i:
            return {"intact": False, "broken_at": path[i]["chain_index"],
                    "reason": "chain index is not contiguous, an entry is missing or duplicated"}
        if path[i].get("prev_hash") != path[i - 1]["row_hash"]:
            return {"intact": False, "broken_at": path[i]["chain_index"], "reason": "previous hash does not match the entry before it"}
    if _entry_digest(entry, path[0]["prev_hash"]) != path[0]["row_hash"]:
        return {"intact": False, "broken_at": index, "reason": "the entry content does not match the digest published for it"}
    head = path[-1]["row_hash"]
    last = int(path[-1]["chain_index"])
    att = doc.get("attestation")
    if not att or not att.get("head_hash"):
        return {"intact": False, "broken_at": last, "reason": "the proof carries no attestation, so it links to nothing anyone signed"}
    if att["head_hash"] != head:
        return {"intact": False, "broken_at": last,
                "reason": "the path produces %s but the signed attestation claims %s" % (head, att["head_hash"])}
    if int(att.get("entries", -1)) != last:
        return {"intact": False, "broken_at": last,
                "reason": "the path ends at entry %d but the attestation covers %s" % (last, att.get("entries"))}
    return {"intact": True, "index": index, "links": len(path), "head_hash": head}


def attestation_payload(att):
    def s(v):
        return "" if v is None else str(v)
    return "|".join(["riskrouter-ledger-attestation", "v1", s(att.get("as_of")), s(att.get("entries")), s(att.get("head_hash"))])


def load_keyring(location):
    """A key file, or a directory of signing-key*.json files: every key we have published.

    Old keys stay published after a rotation, so a signature is checked against the
    key its own key id names, not only against whichever key is current."""
    if os.path.isdir(location):
        names = sorted(n for n in os.listdir(location) if n.startswith("signing-key") and n.endswith(".json"))
        return [_load(os.path.join(location, n)) for n in names]
    return [_load(location)]


def pick_key(published, key_id):
    """The key a signature names, from one key or a keyring; None if it is not there."""
    ring = published if isinstance(published, list) else [published]
    if key_id:
        for k in ring:
            if k.get("key_id") == key_id:
                return k
        return ring[0] if len(ring) == 1 and not ring[0].get("key_id") else None
    return ring[0] if len(ring) == 1 else None


def verify_attestation_signature(doc, published):
    att = doc.get("attestation") or doc
    sig = doc.get("signature")
    if not sig:
        return {"ok": False, "reason": "this file carries no signature, so it proves only that someone had a text editor"}
    payload = attestation_payload(att)
    if sig.get("signed_payload") and sig["signed_payload"] != payload:
        return {"ok": False, "reason": "the signature covers different content than this file claims"}
    key = pick_key(published, sig.get("key_id"))
    if key is None:
        return {"ok": False, "reason": "signed with key %s, which is not among the keys supplied" % (sig.get("key_id") or "(unnamed)")}
    if not ecdsa_p256_verify(key["public_key"], payload.encode("utf-8"), sig.get("signature", "")):
        return {"ok": False, "reason": "the signature does not verify against this key"}
    return {"ok": True}


# ------------------------------------------------------ v2 evidence log (RFC 6962)

EMPTY_ROOT = sha256_hex(b"")


def leaf_hash(leaf_bytes):
    return sha256_hex(b"\x00" + leaf_bytes)


def node_hash(left, right):
    return sha256_hex(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right))


def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root_hash(leaves):
    if not leaves:
        return EMPTY_ROOT
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(root_hash(leaves[:k]), root_hash(leaves[k:]))


def verify_inclusion(index, size, leaf, path, root):
    """RFC 9162 section 2.1.3.2."""
    if not isinstance(index, int) or not isinstance(size, int) or index < 0 or index >= size:
        return False
    if not HEX64.match(leaf or "") or not HEX64.match(root or "") or not all(HEX64.match(p or "") for p in path):
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = node_hash(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first, second, first_root, second_root, path):
    """RFC 9162 section 2.1.4.2."""
    if not isinstance(first, int) or not isinstance(second, int) or first < 1 or first > second:
        return False
    if not HEX64.match(first_root or "") or not HEX64.match(second_root or "") or not all(HEX64.match(p or "") for p in path):
        return False
    if first == second:
        return not path and first_root == second_root
    proof = list(path)
    if first & (first - 1) == 0:
        proof = [first_root] + proof
    if not proof:
        return False
    fn, sn = first - 1, second - 1
    while fn % 2 == 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root


def leaf_string(entry):
    """The frozen leaf string: v2, or v3 when the entry carries the decision-maker's own signature."""
    if int(entry.get("leaf_version") or 2) == 3 or entry.get("signer_key_id"):
        return "|".join(["riskrouter-evidence-leaf", "v3", str(entry["leaf_index"]), entry["created_at"],
                         entry["distributor_id"], entry["kind"], entry["record_digest"],
                         entry["signer_key_id"], entry["claimed_at"], entry["client_signature"]])
    return "|".join(["riskrouter-evidence-leaf", "v2", str(entry["leaf_index"]), entry["created_at"],
                     entry["distributor_id"], entry["kind"], entry["record_digest"]])


def claim_payload(entry):
    """Frozen: what the client signed, before the log assigned anything."""
    return "|".join(["riskrouter-evidence-claim", "v3", entry["kind"], entry["record_digest"],
                     entry["signer_key_id"], entry["claimed_at"]])


def signer_key_id(jwk):
    """A signer's key id, derived as a witness id is: SHA-256 over JSON [x, y], first 16 hex."""
    return hashlib.sha256(json.dumps([jwk["x"], jwk["y"]], separators=(",", ":")).encode("utf-8")).hexdigest()[:16]


def verify_claim(entry, jwk):
    """True only if the entry's client_signature verifies over its claim payload under the signer's JWK."""
    try:
        if signer_key_id(jwk) != entry["signer_key_id"]:
            return False
        return ecdsa_p256_verify(jwk, claim_payload(entry).encode("utf-8"), entry["client_signature"])
    except (KeyError, TypeError):
        return False


# ------------------------------------------------------------ records

# A record is a JSON object whose canonical form is RFC 8785 under a narrow
# profile (docs/regime-packs.md, /spec): keys ^[a-z][a-z0-9_]{0,63}$, integers
# within +/-(2^53 - 1), valid Unicode strings, nesting at most 32 deep. The
# digest is SHA-256(salt || UTF-8(canonical)). Reimplemented here, not shared.

_RECORD_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}\Z")
_SAFE = 2 ** 53 - 1
_SALT = re.compile(r"^(?:[0-9a-f]{2}){16,64}\Z")


def _record_value(v, depth, where):
    if depth > 32:
        raise ValueError("%s: nested more than 32 deep" % where)
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, float):
        # JSON "1.0" is the number 1, as it is in JavaScript; a fraction is refused.
        if v != v or v in (float("inf"), float("-inf")) or not v.is_integer():
            raise ValueError("%s: numbers must be whole; write money as integer cents" % where)
        v = int(v)
    if isinstance(v, int):
        if abs(v) > _SAFE:
            raise ValueError("%s: integers must be within +/-(2^53 - 1)" % where)
        return str(v)
    if isinstance(v, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in v):
            raise ValueError("%s: the string is not valid Unicode (a lone surrogate)" % where)
        # Escapes exactly the characters ECMAScript's JSON.stringify escapes, as RFC 8785 requires.
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(_record_value(x, depth + 1, "%s[%d]" % (where, i)) for i, x in enumerate(v)) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str) or not _RECORD_KEY.match(k):
                raise ValueError("%s: key %r is not lower-case a-z, 0-9 and _ starting with a letter" % (where, k))
        return "{" + ",".join(json.dumps(k) + ":" + _record_value(v[k], depth + 1, "%s.%s" % (where, k)) for k in sorted(v)) + "}"
    raise ValueError("%s: %s is not a JSON value a record may hold" % (where, type(v).__name__))


def canonical_record(record):
    """The canonical form of a record, or ValueError saying why it has none."""
    if not isinstance(record, dict):
        raise ValueError("a record is a JSON object")
    return _record_value(record, 1, "$")


def acceptable_record(record):
    try:
        canonical_record(record)
        return True
    except ValueError:
        return False


def record_digest(salt_hex, record):
    if not isinstance(salt_hex, str) or not _SALT.match(salt_hex):
        raise ValueError("the salt is 16 to 64 bytes written as lowercase hex")
    return sha256_hex(bytes.fromhex(salt_hex) + canonical_record(record).encode("utf-8"))


def verify_record_bundle(doc, published=None):
    """A record, its salt and the evidence proof for its digest. Returns [(ok, line), ...]."""
    lines = []
    record, proof = doc.get("record"), doc.get("proof") or {}
    entry = proof.get("entry") or {}
    try:
        digest = record_digest(doc.get("salt_hex"), record)
    except ValueError as e:
        return [(False, "record: %s" % e)]
    lines.append((digest == entry.get("record_digest"),
                  "the record and its salt produce the recorded digest" if digest == entry.get("record_digest")
                  else "the record and its salt do NOT produce the digest in the proof: this is not the record that was recorded"))
    if "kind" in record or "kind" in entry:
        same = record.get("kind") == entry.get("kind")
        lines.append((same, "its kind %s is the kind recorded" % entry.get("kind") if same
                      else "its kind %r is not the kind recorded, %r" % (record.get("kind"), entry.get("kind"))))
    r = verify_evidence_proof(proof)
    lines.append((r["intact"], "entry %d is in the tree of %d leaves with root %s" % (r["leaf_index"], r["tree_size"], r["root_hash"])
                  if r["intact"] else r["reason"]))
    if r["intact"] and r.get("signer_key_id"):
        lines.append((True, "the signer %s asserted it at %s; its own signature verifies" % (r["signer_key_id"], r["claimed_at"])))
    if published is not None and proof.get("head"):
        sig = verify_head_signature(proof["head"], proof.get("signature"), published)
        lines.append((sig["ok"], "we signed that head" if sig["ok"] else sig["reason"]))
    return lines


# -------------------------------- completeness chains, spot checks, disclosure, co-sealing
# docs/completeness.md, docs/spot-checks.md, docs/selective-disclosure.md and
# docs/co-sealing.md, settled 7 October 2026. Reimplemented here from the
# specification, not shared with the JavaScript; the tests hold them equal.

CHAIN_GENESIS = "0" * 64
_TIME6 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")


def _whole_number(v):
    return isinstance(v, int) and not isinstance(v, bool)


def chain_links_digest(links):
    """SHA-256 over the link lines chain_seq|leaf_index|created_at|record_digest, each ending in a newline."""
    text = "".join("%d|%d|%s|%s\n" % (l["chain_seq"], l["leaf_index"], l["created_at"], l["record_digest"]) for l in links)
    return sha256_hex(text.encode("utf-8"))


def chain_payload(st):
    """Frozen: what the log signs about a chain, as of a signed head."""
    h = st["head"]
    return "|".join(["riskrouter-evidence-chain", "v1", st["chain_tag"], str(st["length"]), str(h["tree_size"]),
                     h["root_hash"], h["timestamp"], str(st["from"]), str(st["to"]), st["links_digest"]])


def select_sample(seed, population, sample):
    """The positions (from 1) a seed selects, in draw order. Frozen; see docs/spot-checks.md."""
    if not isinstance(seed, str) or not HEX64.match(seed):
        raise ValueError("the seed is a block hash: 64 lowercase hex characters")
    if not _whole_number(population) or population < 1 or not _whole_number(sample) or sample < 1:
        raise ValueError("the population and the sample are whole numbers of at least 1")
    limit = (1 << 64) - ((1 << 64) % population)
    want = min(sample, population)
    drawn, counter = [], 0
    while len(drawn) < want:
        h = hashlib.sha256(("riskrouter-spot-check|v1|%s|%d|%d" % (seed, population, counter)).encode("utf-8")).digest()
        counter += 1
        x = int.from_bytes(h[:8], "big")
        if x >= limit:
            continue
        position = x % population + 1
        if position not in drawn:
            drawn.append(position)
    return drawn


def _signed_line(payload, signature, published, what):
    if published is None:
        return (None, "%s: no key supplied (--key), signature not checked" % what)
    if not signature:
        return (False, "%s: carries no signature" % what)
    if signature.get("signed_payload") and signature["signed_payload"] != payload:
        return (False, "%s: the signature covers different content than the file claims" % what)
    key = pick_key(published, signature.get("key_id"))
    if key is None:
        return (False, "%s: signed with key %s, which is not among the keys supplied" % (what, signature.get("key_id") or "(unnamed)"))
    if not ecdsa_p256_verify(key["public_key"], payload.encode("utf-8"), signature.get("signature", "")):
        return (False, "%s: the signature does not verify against the key supplied" % what)
    return (True, "%s: we signed it" % what)


def verify_chain_statement(doc, published=None):
    """One chain statement: contiguous, well-formed links that produce links_digest, signed by us. Returns (lines, links)."""
    lines, links = [], {}
    try:
        if doc.get("format") != "riskrouter-evidence-chain|v1":
            return [(False, "chain: not a riskrouter-evidence-chain|v1 statement")], None
        tag, length, first, last = doc["chain_tag"], doc["length"], doc["from"], doc["to"]
        head = doc["head"]
        size = int(head["tree_size"])
        if not HEX64.match(str(tag)) or not HEX64.match(str(head["root_hash"])):
            return [(False, "chain: the tag or the head is malformed")], None
        if not all(_whole_number(v) for v in (length, first, last)) or length < 0 or first < 1 or last < first - 1 or last > length:
            return [(False, "chain: length, from and to are not a range within the chain")], None
        listed = doc.get("links") or []
        if len(listed) != last - first + 1:
            return [(False, "chain: lists %d links for positions %d to %d" % (len(listed), first, last))], None
        previous_leaf = -1
        for i, l in enumerate(listed):
            if l.get("chain_seq") != first + i:
                return [(False, "chain: the links are not contiguous at position %d" % (first + i))], None
            if not _whole_number(l.get("leaf_index")) or not 0 <= l["leaf_index"] < size or l["leaf_index"] <= previous_leaf:
                return [(False, "chain: position %d names a leaf outside the head's tree, or out of order" % l["chain_seq"])], None
            if not _TIME6.match(str(l.get("created_at"))) or not HEX64.match(str(l.get("record_digest"))):
                return [(False, "chain: position %d is not a well-formed link" % l["chain_seq"])], None
            previous_leaf = l["leaf_index"]
            links[l["chain_seq"]] = l
        if chain_links_digest(listed) != doc.get("links_digest"):
            return [(False, "chain: the links do not produce links_digest: the list was changed")], None
    except (KeyError, TypeError, ValueError, AttributeError):
        return [(False, "chain: not a complete statement")], None
    lines.append((True, "chain %s... has %d records as of tree size %d; positions %d to %d listed and intact" % (tag[:12], length, size, first, last)))
    if doc.get("chain_signature"):
        lines.append(_signed_line(chain_payload(doc), doc["chain_signature"], published, "chain statement"))
    else:
        lines.append((False, "chain statement: unsigned"))
    if doc.get("signature"):
        lines.append(_signed_line(head_payload(head), doc["signature"], published, "evidence head"))
    return lines, links


def _read_statements(pages, published):
    pages = pages if isinstance(pages, list) else ([pages] if pages else [])
    if not pages:
        return [(False, "carries no chain statement")], None
    lines, links = [], {}
    first = pages[0]
    for d in pages:
        l, got = verify_chain_statement(d, published)
        lines.extend(l)
        if got is None:
            return lines, None
        if (d.get("chain_tag"), d.get("length"), d["head"].get("tree_size"), d["head"].get("root_hash")) != \
           (first.get("chain_tag"), first.get("length"), first["head"].get("tree_size"), first["head"].get("root_hash")):
            lines.append((False, "chain: the pages are not one statement (another tag, head or length)"))
            return lines, None
        links.update(got)
    if any(ok is False for ok, _ in lines):
        return lines, None
    return lines, {"links": links, "tag": first["chain_tag"], "length": first["length"], "head": first["head"]}


def _records_by_digest(records, lines):
    found = {}
    for i, r in enumerate(records if isinstance(records, list) else []):
        try:
            found[record_digest(r.get("salt_hex"), r.get("record"))] = r.get("record")
        except (ValueError, AttributeError) as e:
            lines.append((False, "record %d: %s" % (i, e)))
    return found


def _check_position(seq, link, tag, found, previous):
    record = found.get(link["record_digest"])
    if record is None:
        return (False, "position %d: NOT shown. The log holds a record here (leaf %d, sealed %s)" % (seq, link["leaf_index"], link["created_at"]))
    if record.get("chain_tag") != tag or record.get("chain_seq") != seq:
        return (False, "position %d: the record shown says it is elsewhere in the chain, or in another chain" % seq)
    if previous is not None and record.get("chain_prev") != previous:
        return (False, "position %d: chain_prev is not the digest of position %d" % (seq, seq - 1))
    return (True, "position %d: shown, and it is the record sealed (leaf %d)" % (seq, link["leaf_index"]))


def check_completeness(doc, published=None):
    lines, s = _read_statements(doc.get("chain"), published)
    if s is None:
        return lines
    last = s["length"]
    as_of = doc.get("as_of")
    if as_of is not None:
        if not _TIME6.match(str(as_of)):
            return lines + [(False, "as_of is not a time in the form 2026-10-07T12:00:00.000000Z")]
        last = max([seq for seq, l in s["links"].items() if l["created_at"] <= as_of] or [0])
    for seq in range(1, last + 1):
        if seq not in s["links"]:
            return lines + [(False, "chain: position %d is not in the statements supplied" % seq)]
    found = _records_by_digest(doc.get("records"), lines)
    previous, gaps = CHAIN_GENESIS, 0
    for seq in range(1, last + 1):
        link = s["links"][seq]
        line = _check_position(seq, link, s["tag"], found, previous)
        gaps += 0 if line[0] else 1
        lines.append(line)
        previous = link["record_digest"]
    lines.append((True, "complete: all %d records of the chain are shown, in order, none missing" % last) if gaps == 0
                 else (False, "NOT complete: %d of %d positions not shown or not the record sealed" % (gaps, last)))
    return lines


def check_spot_check(doc, published=None):
    lines, s = _read_statements(doc.get("chain"), published)
    if s is None:
        return lines
    try:
        selected = select_sample(doc.get("seed"), s["length"], doc.get("sample_size"))
    except ValueError as e:
        return lines + [(False, "spot check: %s" % e)]
    lines.append((True, "spot check: the seed selects %d of %d positions: %s" % (len(selected), s["length"], ", ".join(str(p) for p in sorted(selected)))))
    lines.append((None, "spot check: confirm yourself that block %s has hash %s, and that its height was announced before it was mined"
                  % (doc.get("bitcoin_height", "(height not given)"), doc.get("seed"))))
    found = _records_by_digest(doc.get("records"), lines)
    missing = 0
    for seq in selected:
        link = s["links"].get(seq)
        if link is None:
            lines.append((False, "position %d: not in the statements supplied" % seq))
            missing += 1
            continue
        before = s["links"].get(seq - 1)
        previous = CHAIN_GENESIS if seq == 1 else (before["record_digest"] if before else None)
        line = _check_position(seq, link, s["tag"], found, previous)
        missing += 0 if line[0] else 1
        lines.append(line)
    lines.append((True, "spot check passed: all %d selected records are shown and are the records sealed" % len(selected)) if missing == 0
                 else (False, "spot check FAILED: %d of %d selected records not shown or not the record sealed" % (missing, len(selected))))
    return lines


def field_salt(secret_hex, name):
    """HMAC-SHA256(secret, "riskrouter-disclosable|1|" || name): one salt per field, from a secret that never leaves the firm."""
    if not isinstance(secret_hex, str) or not _SALT.match(secret_hex):
        raise ValueError("the disclosure secret is 16 to 64 bytes written as lowercase hex")
    if not _RECORD_KEY.match(name):
        raise ValueError("field %r is not a record key" % name)
    return hmac.new(bytes.fromhex(secret_hex), ("riskrouter-disclosable|1|" + name).encode("utf-8"), hashlib.sha256).hexdigest()


def field_commitment(field_salt_hex, name, value):
    if not isinstance(field_salt_hex, str) or not HEX64.match(field_salt_hex):
        raise ValueError("a field salt is 32 bytes of lowercase hex")
    return sha256_hex(bytes.fromhex(field_salt_hex) + canonical_record({name: value}).encode("utf-8"))


def sealed_record(record, secret_hex):
    canonical_record(record)
    sealed = {"format": "riskrouter-disclosable|1",
              "fields": {k: field_commitment(field_salt(secret_hex, k), k, record[k]) for k in sorted(record)}}
    if isinstance(record.get("kind"), str):
        sealed["kind"] = record["kind"]
    return sealed


def verify_disclosure(doc, published=None):
    """A selective disclosure: the sealed record and its proof, and each field shown against its commitment."""
    sealed = doc.get("record")
    ok_shape = (isinstance(sealed, dict) and sealed.get("format") == "riskrouter-disclosable|1"
                and isinstance(sealed.get("fields"), dict) and set(sealed) <= {"format", "kind", "fields"}
                and all(_RECORD_KEY.match(k) and isinstance(c, str) and HEX64.match(c) for k, c in sealed["fields"].items()))
    if not ok_shape:
        return [(False, "disclosure: the sealed record is not a riskrouter-disclosable|1 commitment record")]
    lines = verify_record_bundle(doc, published)
    shown = doc.get("disclosed") if isinstance(doc.get("disclosed"), dict) else {}
    if not shown:
        lines.append((False, "disclosure: discloses no field"))
    for name, d in shown.items():
        try:
            c = field_commitment((d or {}).get("field_salt_hex"), name, (d or {}).get("value"))
        except ValueError as e:
            lines.append((False, "disclosure: %s: %s" % (name, e)))
            continue
        if name not in sealed["fields"]:
            lines.append((False, "disclosure: %s is not a field of the sealed record" % name))
        elif c == sealed["fields"][name]:
            lines.append((True, "disclosure: %s = %s is the value sealed" % (name, json.dumps(d["value"], ensure_ascii=False)[:80])))
        else:
            lines.append((False, "disclosure: %s: the value and its salt do NOT produce the sealed commitment" % name))
    hidden = sorted(set(sealed["fields"]) - set(shown))
    if hidden:
        lines.append((True, "disclosure: %d other fields stay sealed (%s)" % (len(hidden), ", ".join(hidden))))
    return lines


def verify_coseal(doc, published=None):
    """Two or more parties sealed the same digest, each as a signed entry under its own key and its own account."""
    bundles = doc.get("bundles") if isinstance(doc.get("bundles"), list) else []
    if len(bundles) < 2:
        return [(False, "co-seal: needs the bundles of at least two parties")]
    lines, entries = [], []
    for i, b in enumerate(bundles):
        check = verify_disclosure if (b or {}).get("format") == "riskrouter-disclosure-bundle|1" else verify_record_bundle
        for ok, line in check(b or {}, published):
            lines.append((ok, "party %d: %s" % (i + 1, line)))
        proof = (b or {}).get("proof") or {}
        entries.append((proof.get("entry") or {}, proof.get("signer_public_key")))
    digests = {e.get("record_digest") for e, _ in entries}
    lines.append((len(digests) == 1, "co-seal: every party sealed the same record digest" if len(digests) == 1
                   else "co-seal: the parties sealed different digests; this is not one record"))
    unsigned = sum(1 for e, _ in entries if int(e.get("leaf_version") or 2) != 3)
    if unsigned:
        lines.append((False, "co-seal: %d entries are not signed by their party (a v3 leaf is needed)" % unsigned))
    else:
        signers = {e.get("signer_key_id") for e, _ in entries}
        owners = {e.get("distributor_id") for e, _ in entries}
        lines.append((len(signers) == len(entries), "co-seal: %d different signers" % len(signers) if len(signers) == len(entries)
                      else "co-seal: one key signed more than one of the entries; that is not two parties"))
        lines.append((len(owners) == len(entries), "co-seal: recorded by %d different distributors" % len(owners) if len(owners) == len(entries)
                      else "co-seal: the entries were recorded by the same distributor; that is not two parties"))
    pinned = doc.get("expected_signers")
    if isinstance(pinned, list):
        for i, want in enumerate(pinned):
            got = entries[i][1] if i < len(entries) else None
            same = bool(got and want and got.get("x") == want.get("x") and got.get("y") == want.get("y") and got.get("crv") == want.get("crv"))
            lines.append((same, "co-seal: party %d signed with the key you pinned for it" % (i + 1) if same
                          else "co-seal: party %d did NOT sign with the key you pinned for it" % (i + 1)))
    else:
        lines.append((None, "co-seal: no expected_signers pinned; check each party's key against one it published itself"))
    return lines


# ------------------------------------------------ RFC 3161 time-stamp tokens
# docs/legal-time.md. A token is the authority's signed statement that it saw
# SHA-256(UTF-8(our signed payload)) at genTime. Checked here with our own DER
# reader, X.509 parsing, RSA PKCS#1 v1.5 and ECDSA P-256: nothing is shared
# with the JavaScript verifier, and no network is used.

_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
_OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
_OID_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"
_OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
_OID_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"
_OID_EKU = "2.5.29.37"
_HASH_OIDS = {"2.16.840.1.101.3.4.2.1": "sha256", "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512"}
_SIG_OIDS = {
    "1.2.840.113549.1.1.1": ("rsa", None), "1.2.840.113549.1.1.11": ("rsa", "sha256"),
    "1.2.840.113549.1.1.12": ("rsa", "sha384"), "1.2.840.113549.1.1.13": ("rsa", "sha512"),
    "1.2.840.10045.4.3.2": ("ecdsa", "sha256"),
}
_DIGEST_INFO = {  # DER DigestInfo prefixes, with and without the NULL parameters
    "sha256": (bytes.fromhex("3031300d060960864801650304020105000420"), bytes.fromhex("302f300b0609608648016503040201")),
    "sha384": (bytes.fromhex("3041300d060960864801650304020205000430"), bytes.fromhex("303f300b0609608648016503040202")),
    "sha512": (bytes.fromhex("3051300d060960864801650304020305000440"), bytes.fromhex("304f300b0609608648016503040203")),
}
_NAME_OIDS = {"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
              "2.5.4.5": "serialNumber", "2.5.4.97": "organizationIdentifier"}


def _tlv(buf, pos=0):
    """(tag, start, value_start, end) of the DER element at pos."""
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise ValueError("high tag numbers are not used here")
    length = buf[pos + 1]
    p = pos + 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4:
            raise ValueError("indefinite or oversized length")
        length = int.from_bytes(buf[p:p + n], "big")
        p += n
    if p + length > len(buf):
        raise ValueError("truncated")
    return tag, pos, p, p + length


def _kids(buf, node):
    out, p = [], node[2]
    while p < node[3]:
        c = _tlv(buf, p)
        out.append(c)
        p = c[3]
    return out


def _val(buf, node):
    return buf[node[2]:node[3]]


def _whole(buf, node):
    return buf[node[1]:node[3]]


def _oid(b):
    parts, v = [b[0] // 40, b[0] % 40], 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(v)
            v = 0
    return ".".join(str(p) for p in parts)


def _need(node, tag, what):
    if node is None or node[0] != tag:
        raise ValueError("%s is not where RFC 3161 puts it" % what)
    return node


def _der_time(tag, raw):
    s = raw.decode("ascii")
    if tag == 0x17:  # UTCTime, YYMMDDHHMMSSZ
        s = ("19" if int(s[:2]) >= 50 else "20") + s
    m = re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$", s)
    if not m:
        raise ValueError("time %s is not UTC" % s)
    return "%s-%s-%sT%s:%s:%s%sZ" % (m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6), m.group(7) or "")


def _name(buf, node):
    parts = []
    for rdn in _kids(buf, node):
        for atv in _kids(buf, rdn):
            t, v = _kids(buf, atv)
            parts.append("%s=%s" % (_NAME_OIDS.get(_oid(_val(buf, t)), _oid(_val(buf, t))), _val(buf, v).decode("utf-8", "replace")))
    return ", ".join(parts)


class _Cert(object):
    def __init__(self, der):
        self.der = bytes(der)
        b = self.der
        top = _kids(b, _tlv(b))
        self.tbs = _whole(b, top[0])
        self.sig_alg = _oid(_val(b, _kids(b, top[1])[0]))
        self.sig = _val(b, top[2])[1:]  # BIT STRING, no unused bits
        t = _kids(b, top[0])
        if t[0][0] == 0xA0:
            t = t[1:]
        self.serial = _val(b, t[0]).hex().lstrip("0") or "0"
        self.issuer_der, self.subject_der = _whole(b, t[2]), _whole(b, t[4])
        self.issuer, self.subject = _name(b, t[2]), _name(b, t[4])
        nb, na = _kids(b, t[3])
        self.not_before, self.not_after = _der_time(nb[0], _val(b, nb)), _der_time(na[0], _val(b, na))
        spki = _kids(b, t[5])
        alg = _kids(b, spki[0])
        key_bits = _val(b, spki[1])[1:]
        self.key_type = _oid(_val(b, alg[0]))
        if self.key_type == "1.2.840.113549.1.1.1":
            n, e = _kids(key_bits, _tlv(key_bits))
            self.rsa = (int.from_bytes(_val(key_bits, n), "big"), int.from_bytes(_val(key_bits, e), "big"))
        elif self.key_type == "1.2.840.10045.2.1" and len(alg) > 1 and _oid(_val(b, alg[1])) == "1.2.840.10045.3.1.7" and key_bits[:1] == b"\x04":
            self.ec = (int.from_bytes(key_bits[1:33], "big"), int.from_bytes(key_bits[33:65], "big"))
        self.eku = []
        for ext in t[6:]:
            if ext[0] != 0xA3:
                continue
            for e in _kids(b, _kids(b, ext)[0]):
                ek = _kids(b, e)
                if _oid(_val(b, ek[0])) == _OID_EKU:
                    inner = _val(b, ek[-1])
                    self.eku = [_oid(_val(inner, o)) for o in _kids(inner, _tlv(inner))]
        self.fingerprint256 = ":".join("%02X" % x for x in hashlib.sha256(self.der).digest())

    def verify(self, kind, hash_name, message, signature):
        digest = hashlib.new(hash_name, message).digest()
        if kind == "rsa" and hasattr(self, "rsa"):
            n, e = self.rsa
            k = (n.bit_length() + 7) // 8
            if len(signature) != k:
                return False
            em = pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")
            for prefix in _DIGEST_INFO[hash_name]:
                t = prefix + digest
                if em == b"\x00\x01" + b"\xff" * (k - 3 - len(t)) + b"\x00" + t:
                    return True
            return False
        if kind == "ecdsa" and hasattr(self, "ec") and hash_name == "sha256":
            r, s = _kids(signature, _tlv(signature))
            raw = int.from_bytes(_val(signature, r), "big").to_bytes(32, "big") + int.from_bytes(_val(signature, s), "big").to_bytes(32, "big")
            jwk = {"kty": "EC", "crv": "P-256",
                   "x": base64.urlsafe_b64encode(self.ec[0].to_bytes(32, "big")).decode().rstrip("="),
                   "y": base64.urlsafe_b64encode(self.ec[1].to_bytes(32, "big")).decode().rstrip("=")}
            return ecdsa_p256_verify(jwk, message, base64.b64encode(raw).decode())
        return False

    def issued(self, issuer):
        if self.issuer_der != issuer.subject_der or self.sig_alg not in _SIG_OIDS:
            return False
        kind, h = _SIG_OIDS[self.sig_alg]
        return h is not None and issuer.verify(kind, h, self.tbs, self.sig)


def verify_tst_token(token, imprint, nonce=None):
    """A DER TimeStampToken against the imprint it should carry: {"ok": True, ...} or {"ok": False, "reason"}."""
    try:
        b = bytes(token)
        ci = _kids(b, _need(_tlv(b), 0x30, "the token"))
        if _oid(_val(b, ci[0])) != _OID_SIGNED_DATA:
            return {"ok": False, "reason": "the token is not CMS SignedData"}
        sd = _kids(b, _need(_kids(b, _need(ci[1], 0xA0, "the signed data"))[0], 0x30, "the signed data"))
        encap = _kids(b, sd[2])
        if _oid(_val(b, encap[0])) != _OID_TST_INFO:
            return {"ok": False, "reason": "the signed content is not a TSTInfo"}
        econtent = _val(b, _need(_kids(b, _need(encap[1], 0xA0, "the content"))[0], 0x04, "the content"))
        certs = [_Cert(_whole(b, c)) for n in sd[3:-1] if n[0] == 0xA0 for c in _kids(b, n) if c[0] == 0x30]
        tb = econtent
        tst = _kids(tb, _need(_tlv(tb), 0x30, "the TSTInfo"))
        mi = _kids(tb, tst[2])
        if _oid(_val(tb, _kids(tb, mi[0])[0])) != "2.16.840.1.101.3.4.2.1":
            return {"ok": False, "reason": "the imprint does not use SHA-256"}
        if _val(tb, mi[1]) != bytes(imprint):
            return {"ok": False, "reason": "the token is for a different digest: it does not timestamp this payload"}
        gen_time = _der_time(0x18, _val(tb, _need(tst[4], 0x18, "genTime")))
        token_nonce = next((_val(tb, n).hex().lstrip("0") or "0" for n in tst[5:] if n[0] == 0x02), None)
        if nonce is not None and token_nonce != (nonce.hex().lstrip("0") or "0"):
            return {"ok": False, "reason": "the token does not carry the nonce that was sent"}
        infos = _kids(b, _need(sd[-1], 0x31, "the signer infos"))
        if len(infos) != 1:
            return {"ok": False, "reason": "the token has %d signers, not one" % len(infos)}
        si = _kids(b, infos[0])
        digest_oid = _oid(_val(b, _kids(b, si[2])[0]))
        if digest_oid not in _HASH_OIDS:
            return {"ok": False, "reason": "SHA-1 is not accepted" if digest_oid == "1.3.14.3.2.26" else "unsupported digest %s" % digest_oid}
        h = _HASH_OIDS[digest_oid]
        attrs_node = _need(si[3], 0xA0, "the signed attributes")
        attrs = {}
        for a in _kids(b, attrs_node):
            t, vals = _kids(b, a)
            attrs[_oid(_val(b, t))] = _kids(b, vals)
        if _OID_CONTENT_TYPE not in attrs or _oid(_val(b, attrs[_OID_CONTENT_TYPE][0])) != _OID_TST_INFO:
            return {"ok": False, "reason": "the signed attributes do not say the content is a TSTInfo"}
        if _OID_MESSAGE_DIGEST not in attrs or _val(b, attrs[_OID_MESSAGE_DIGEST][0]) != hashlib.new(h, econtent).digest():
            return {"ok": False, "reason": "the signed attributes do not bind this TSTInfo: it was changed after signing"}
        sig_oid = _oid(_val(b, _kids(b, si[4])[0]))
        if sig_oid not in _SIG_OIDS:
            return {"ok": False, "reason": "unsupported signature algorithm %s" % sig_oid}
        kind, sig_hash = _SIG_OIDS[sig_oid]
        signed = b"\x31" + bytes(_whole(b, attrs_node))[1:]
        signature = _val(b, _need(si[5], 0x04, "the signature"))
        sid = si[1]
        want = (_val(b, _kids(b, sid)[1]).hex().lstrip("0") or "0") if sid[0] == 0x30 else None
        signer = next((c for c in certs if (want is None or c.serial == want) and c.verify(kind, sig_hash or h, signed, signature)), None)
        if signer is None:
            return {"ok": False, "reason": "the authority's signature does not verify with the certificate the token carries"
                    if certs else "the token carries no certificate to check its signature with"}
        ess = attrs.get(_OID_SIGNING_CERT_V2) or attrs.get(_OID_SIGNING_CERT)
        if ess:
            first = _kids(b, _kids(b, ess[0])[0])[0]
            cid = _kids(b, first)
            ess_hash, hash_node = ("sha256" if _OID_SIGNING_CERT_V2 in attrs else "sha1"), cid[0]
            if _OID_SIGNING_CERT_V2 in attrs and cid[0][0] == 0x30:
                ess_hash, hash_node = _HASH_OIDS.get(_oid(_val(b, _kids(b, cid[0])[0]))), cid[1]
            if not ess_hash or _val(b, hash_node) != hashlib.new(ess_hash, signer.der).digest():
                return {"ok": False, "reason": "the signing-certificate attribute names a different certificate"}
        if _OID_TIME_STAMPING not in signer.eku:
            return {"ok": False, "reason": "the signing certificate is not for time-stamping (no id-kp-timeStamping)"}
        if not (signer.not_before <= gen_time[:19] + "Z" <= signer.not_after):
            return {"ok": False, "reason": "genTime is outside the signing certificate's validity"}
        chain = [signer]
        while len(chain) < 8 and not chain[-1].issued(chain[-1]):
            up = next((c for c in certs if c not in chain and chain[-1].issued(c)), None)
            if up is None:
                break
            chain.append(up)
        return {"ok": True, "gen_time": gen_time, "tsa": signer.subject, "root": chain[-1].subject,
                "root_fingerprint256": chain[-1].fingerprint256, "root_self_signed": chain[-1].issued(chain[-1])}
    except (ValueError, IndexError, KeyError) as e:
        return {"ok": False, "reason": "the token cannot be read: %s" % e}


_QUALIFIED_LIST = re.compile(r"^https://(eidas\.ec\.europa\.eu|esignature\.ec\.europa\.eu)/")


def verify_head_timestamp(doc, published=None):
    """A riskrouter-head-timestamp|1 file: [(ok, line), ...]; ok None is a note."""
    lines = []
    signed = doc.get("signed") or {}
    if "head" in signed:
        subject, payload = "riskrouter-evidence-head|v2", head_payload(signed["head"])
    elif "attestation" in signed:
        subject, payload = "riskrouter-ledger-attestation|v1", attestation_payload(signed["attestation"])
    else:
        return [(False, "the file carries no head")]
    if doc.get("subject") != subject or doc.get("payload") != payload:
        return [(False, "the payload is not the one the head it carries produces")]
    if published is not None:
        sig = doc.get("signature") or {}
        key = pick_key(published, sig.get("key_id"))
        ok = key is not None and ecdsa_p256_verify(key["public_key"], payload.encode("utf-8"), sig.get("signature", ""))
        lines.append((ok, "our signature on the head verifies" if ok else "our signature on the head does not verify"))
    r = verify_tst_token(base64.b64decode(doc.get("token", "")), hashlib.sha256(payload.encode("utf-8")).digest())
    if not r["ok"]:
        return lines + [(False, "RFC 3161 token: %s" % r["reason"])]
    if doc.get("gen_time") and doc["gen_time"] != r["gen_time"]:
        lines.append((False, "the file says %s but the token says %s" % (doc["gen_time"], r["gen_time"])))
    tsa = doc.get("tsa") or {}
    lines.append((True, "RFC 3161 token: %s states it saw this head at %s" % (tsa.get("name") or r["tsa"], r["gen_time"])))
    lines.append((None, "chain carried in the token ends at %s%s (SHA-256 %s); compare it with the root the authority publishes"
                  % (r["root"], ", self-signed" if r["root_self_signed"] else "", r["root_fingerprint256"])))
    if tsa.get("qualified") is True:
        if _QUALIFIED_LIST.match(str(tsa.get("trusted_list") or "")):
            lines.append((None, "listed by the operator as a qualified eIDAS time stamp; check the entry: %s" % tsa["trusted_list"]))
        else:
            lines.append((False, "the file calls this a qualified time stamp but names no EU Trusted List entry"))
    else:
        lines.append((None, "not a qualified eIDAS time stamp: evidence of time, without the presumption a qualified one carries"))
    return lines


def head_payload(head):
    return "|".join(["riskrouter-evidence-head", "v2", str(head["tree_size"]), head["root_hash"], head["timestamp"]])


def cosign_payload(witness_id, tree_size, root, cosigned_at):
    return "|".join(["riskrouter-evidence-cosign", "v2", witness_id, str(tree_size), root, cosigned_at])


def verify_head_signature(head, signature, published):
    if not signature:
        return {"ok": False, "reason": "the head carries no signature"}
    payload = head_payload(head)
    if signature.get("signed_payload") and signature["signed_payload"] != payload:
        return {"ok": False, "reason": "the signature covers different content than the head claims"}
    key = pick_key(published, signature.get("key_id"))
    if key is None:
        return {"ok": False, "reason": "signed with key %s, which is not among the keys supplied" % (signature.get("key_id") or "(unnamed)")}
    if not ecdsa_p256_verify(key["public_key"], payload.encode("utf-8"), signature.get("signature", "")):
        return {"ok": False, "reason": "the head signature does not verify against the published key"}
    return {"ok": True}


def verify_evidence_proof(doc, saved_head=None, signer_public_key=None):
    """A v2 proof, against the head it carries or a head the holder saved; a v3 leaf's client signature is checked too."""
    entry = doc.get("entry") or {}
    try:
        leaf = leaf_hash(leaf_string(entry).encode("utf-8"))
    except (KeyError, TypeError):
        return {"intact": False, "reason": "the proof carries no complete entry"}
    if entry.get("leaf_hash") and entry["leaf_hash"] != leaf:
        return {"intact": False, "reason": "the entry does not produce the leaf hash it claims"}
    head = saved_head or doc.get("head")
    if not head:
        return {"intact": False, "reason": "no head to check against: pass the head you saved with --saved-head"}
    if int(head["tree_size"]) != int(doc.get("tree_size", -1)):
        return {"intact": False, "reason": "the proof is for tree_size %s but the head is for %s" % (doc.get("tree_size"), head["tree_size"])}
    if not verify_inclusion(int(entry["leaf_index"]), int(head["tree_size"]), leaf, doc.get("audit_path") or [], head["root_hash"]):
        return {"intact": False, "reason": "the audit path does not lead from this entry to the head's root"}
    result = {"intact": True, "leaf_index": int(entry["leaf_index"]), "tree_size": int(head["tree_size"]), "root_hash": head["root_hash"]}
    if int(entry.get("leaf_version") or 2) == 3:
        # A v3 leaf carries the decision-maker's own signature; a proof of one is
        # not intact unless that signature verifies too. The key comes with the
        # proof (signer_public_key); pass --signer-key to use one the signer
        # published instead, which is the stronger check.
        key = signer_public_key or doc.get("signer_public_key")
        if not key:
            return {"intact": False, "reason": "a v3 leaf, but no signer key to verify the client signature with"}
        if not verify_claim(entry, key):
            return {"intact": False, "reason": "the client signature does not verify over the claim payload with the signer's key"}
        result["signer_key_id"] = entry["signer_key_id"]
        result["claimed_at"] = entry["claimed_at"]
    return result


def verify_consistency_doc(doc, saved_head):
    head = doc.get("head")
    if not head:
        return {"intact": False, "reason": "the proof carries no current head"}
    if int(saved_head["tree_size"]) != int(doc.get("first", -1)):
        return {"intact": False, "reason": "the proof starts at %s but the head you saved has %s leaves" % (doc.get("first"), saved_head["tree_size"])}
    if int(head["tree_size"]) != int(doc.get("second", -1)):
        return {"intact": False, "reason": "the proof ends at a different size than its head"}
    ok = verify_consistency(int(saved_head["tree_size"]), int(head["tree_size"]), saved_head["root_hash"], head["root_hash"], doc.get("proof") or [])
    if not ok:
        return {"intact": False, "reason": "the current head is NOT consistent with the head you saved: history was rewritten"}
    return {"intact": True, "first": int(saved_head["tree_size"]), "second": int(head["tree_size"])}


def verify_cosignature(doc, witness_key, published=None):
    if doc.get("format") != "riskrouter-evidence-cosignature|v2":
        return {"ok": False, "reason": "not a cosignature file"}
    if doc.get("witness_id") != witness_key.get("witness_id"):
        return {"ok": False, "reason": "signed by %s, not %s" % (doc.get("witness_id"), witness_key.get("witness_id"))}
    head = doc["head"]
    payload = cosign_payload(doc["witness_id"], head["tree_size"], head["root_hash"], doc["cosigned_at"])
    sig = doc.get("cosignature") or {}
    if sig.get("signed_payload") and sig["signed_payload"] != payload:
        return {"ok": False, "reason": "the cosignature covers different content than the file claims"}
    if not ecdsa_p256_verify(witness_key["public_key"], payload.encode("utf-8"), sig.get("signature", "")):
        return {"ok": False, "reason": "the witness signature does not verify"}
    if published is not None:
        ours = verify_head_signature(head, doc.get("head_signature"), published)
        if not ours["ok"]:
            return {"ok": False, "reason": "the head it witnessed is not one we signed: " + ours["reason"]}
    return {"ok": True, "tree_size": head["tree_size"], "root_hash": head["root_hash"]}


# ------------------------------------ C2SP checkpoints and cosignatures (Ed25519)
# c2sp.org/signed-note, tlog-checkpoint and tlog-cosignature, as the public
# witness network speaks them (docs/transparency-log.md). Ed25519 verification
# from RFC 8032, section 5.1.7, in plain integers.

_ED_P = 2 ** 255 - 19
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, _ED_P - 2, _ED_P) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _ED_P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _ED_P
    c = 2 * p[3] * q[3] * _ED_D % _ED_P
    d = 2 * p[2] * q[2] % _ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P)


def _ed_mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        s >>= 1
    return q


def _ed_equal(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % _ED_P == 0 and (p[1] * q[2] - q[1] * p[2]) % _ED_P == 0


def _ed_recover_x(y, sign):
    if y >= _ED_P:
        return None
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = x * _ED_I % _ED_P
    if (x * x - x2) % _ED_P != 0:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x


def _ed_decompress(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _ED_P)


_ED_GY = 4 * pow(5, _ED_P - 2, _ED_P) % _ED_P
_ED_G = (_ed_recover_x(_ED_GY, 0), _ED_GY, 1, _ed_recover_x(_ED_GY, 0) * _ED_GY % _ED_P)


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _ed_decompress(public)
    r = _ed_decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED_L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _ED_L
    return _ed_equal(_ed_mul(s, _ED_G), _ed_add(r, _ed_mul(h, a)))


def note_key_id(name, sig_type, public):
    return hashlib.sha256(name.encode("utf-8") + b"\n" + bytes([sig_type]) + public).digest()[:4].hex()


def parse_vkey(vkey):
    # The key material is base64, which may itself contain "+": split at the first two only.
    parts = vkey.strip().split("+", 2)
    if len(parts) != 3 or not parts[0] or re.search(r"\s", parts[0]):
        raise ValueError("a vkey is name+keyid+key")
    name, kid, material = parts
    raw = base64.b64decode(material, validate=True)
    if raw[0] not in (0x01, 0x04) or len(raw) != 33:
        raise ValueError("only Ed25519 note keys (0x01) and cosignature/v1 keys (0x04) are supported")
    if note_key_id(name, raw[0], raw[1:]) != kid:
        raise ValueError("the vkey's key ID does not match its name and key")
    return {"name": name, "id": kid, "type": raw[0], "public": raw[1:]}


def parse_note(note):
    if re.search(r"[\x00-\x09\x0b-\x1f]", note):
        raise ValueError("a note may contain no control characters other than newline")
    split = note.rfind("\n\n")
    if split < 0 or not note.endswith("\n"):
        raise ValueError("a note has a text, a blank line, then signatures")
    text = note[:split + 1]
    sigs = []
    for line in note[split + 2:-1].split("\n"):
        m = re.match(r"^— (\S+) ([A-Za-z0-9+/]+={0,2})$", line)
        if not m:
            raise ValueError("not a signature line: " + line[:80])
        raw = base64.b64decode(m.group(2), validate=True)
        sigs.append({"name": m.group(1), "id": raw[:4].hex(), "sig": raw[4:]})
    return text, sigs


def verify_note(note, vkeys):
    """c2sp.org/signed-note: unknown keys are ignored, a known key that fails rejects the note, one must verify."""
    try:
        text, sigs = parse_note(note)
    except ValueError as e:
        return {"ok": False, "reason": str(e)}
    verified = []
    for s in sigs:
        k = next((k for k in vkeys if k["name"] == s["name"] and k["id"] == s["id"]), None)
        if k is None:
            continue
        if k["type"] == 0x01:
            ok, ts = len(s["sig"]) == 64 and ed25519_verify(k["public"], text.encode("utf-8"), s["sig"]), None
        else:
            ts = int.from_bytes(s["sig"][:8], "big") if len(s["sig"]) == 72 else None
            message = ("cosignature/v1\ntime %d\n" % ts + text).encode("utf-8") if ts is not None else b""
            ok = ts is not None and ed25519_verify(k["public"], message, s["sig"][8:])
        if not ok:
            return {"ok": False, "reason": "the signature by %s (%s) does not verify" % (s["name"], s["id"])}
        verified.append({"name": k["name"], "type": k["type"], "timestamp": ts})
    if not verified:
        return {"ok": False, "reason": "no signature from a key you trust"}
    return {"ok": True, "text": text, "verified": verified}


def parse_checkpoint(text):
    lines = text.split("\n")
    if lines.pop() != "" or len(lines) < 3 or any(not l for l in lines):
        raise ValueError("a checkpoint has an origin, a size and a root, each on its own line")
    if not re.match(r"^(0|[1-9][0-9]*)$", lines[1]):
        raise ValueError("the size is a decimal with no leading zeroes")
    root = base64.b64decode(lines[2], validate=True)
    if len(root) != 32:
        raise ValueError("the root is 32 bytes")
    return {"origin": lines[0], "tree_size": int(lines[1]), "root_hash": root.hex(), "extensions": lines[3:]}


def verify_checkpoint(note, log_vkey, witness_vkeys=()):
    """Our signature must verify; each known witness's cosignature is checked and reported."""
    log_key = parse_vkey(log_vkey)
    results = []
    ours = verify_note(note, [log_key])
    if not ours["ok"]:
        return [(False, ours["reason"])]
    cp = parse_checkpoint(ours["text"])
    if cp["origin"] != log_key["name"]:
        return [(False, "the checkpoint names origin %s, not %s" % (cp["origin"], log_key["name"]))]
    results.append((True, "our signature holds: tree_size %d, root %s, origin %s" % (cp["tree_size"], cp["root_hash"], cp["origin"])))
    for wv in witness_vkeys:
        wk = parse_vkey(wv)
        if not any(l.startswith("— %s " % wk["name"]) for l in note.split("\n")):
            continue
        w = verify_note(note, [wk])
        results.append((w["ok"], "%s cosigned it at %s" % (wk["name"], datetime.fromtimestamp(w["verified"][0]["timestamp"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
                        if w["ok"] else "%s: %s" % (wk["name"], w["reason"])))
    return results


# ------------------------------------------------------ SCITT COSE Receipts
# RFC 9942 receipts from the log (docs/scitt.md): COSE_Sign1, ES256, vds 395 = 1
# (RFC9162_SHA256), inclusion proof at vdp 396 / -1, detached payload = the root.
# A small strict CBOR reader and writer, enough for these structures.

class _Tag(object):
    def __init__(self, tag, value):
        self.tag, self.value = tag, value


def cbor_decode(data):
    pos = [0]

    def need(n):
        if pos[0] + n > len(data):
            raise ValueError("CBOR ends early")

    def arg(info):
        if info < 24:
            return info
        size = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
        if size is None:
            raise ValueError("indefinite lengths are not accepted")
        need(size)
        v = int.from_bytes(data[pos[0]:pos[0] + size], "big")
        pos[0] += size
        return v

    def item(depth):
        if depth > 16:
            raise ValueError("CBOR nested too deep")
        need(1)
        ib = data[pos[0]]
        pos[0] += 1
        major, info = ib >> 5, ib & 0x1F
        if major == 7:
            simple = {20: False, 21: True, 22: None}
            if info not in simple:
                raise ValueError("floats and simple values are not accepted")
            return simple[info]
        n = arg(info)
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major in (2, 3):
            need(n)
            v = data[pos[0]:pos[0] + n]
            pos[0] += n
            return bytes(v) if major == 2 else v.decode("utf-8")
        if major == 4:
            return [item(depth + 1) for _ in range(n)]
        if major == 5:
            m = {}
            for _ in range(n):
                k = item(depth + 1)
                if k in m:
                    raise ValueError("a map key appears twice")
                m[k] = item(depth + 1)
            return m
        if major == 6:
            return _Tag(n, item(depth + 1))
        raise ValueError("unknown CBOR major type")

    v = item(0)
    if pos[0] != len(data):
        raise ValueError("bytes after the CBOR item")
    return v


def _cbor_head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    for size, info in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if n < 256 ** size:
            return bytes([(major << 5) | info]) + n.to_bytes(size, "big")
    raise ValueError("too large")


def cbor_encode(v):
    """Enough for Sig_structure and a registered statement: text, bytes, arrays, maps, tags, small ints."""
    if isinstance(v, _Tag):
        return _cbor_head(6, v.tag) + cbor_encode(v.value)
    if isinstance(v, bytes):
        return _cbor_head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _cbor_head(3, len(b)) + b
    if isinstance(v, list):
        return _cbor_head(4, len(v)) + b"".join(cbor_encode(x) for x in v)
    if isinstance(v, dict):
        return _cbor_head(5, len(v)) + b"".join(cbor_encode(k) + cbor_encode(x) for k, x in v.items())
    if isinstance(v, int) and not isinstance(v, bool):
        return _cbor_head(0, v) if v >= 0 else _cbor_head(1, -1 - v)
    raise ValueError("cannot encode %r" % (v,))


def _sign1(data):
    t = cbor_decode(data)
    if not isinstance(t, _Tag) or t.tag != 18 or not isinstance(t.value, list) or len(t.value) != 4:
        raise ValueError("not a tagged COSE_Sign1")
    prot_bytes, unprot, payload, sig = t.value
    return prot_bytes, (cbor_decode(prot_bytes) if prot_bytes else {}), unprot, payload, sig


def statement_digest(data):
    """SHA-256 of the Signed Statement with its unprotected header emptied: its record_digest in the log."""
    prot_bytes, _, _, payload, sig = _sign1(data)
    return hashlib.sha256(cbor_encode(_Tag(18, [prot_bytes, {}, payload, sig]))).hexdigest()


def _root_from_path(index, size, leaf, path):
    if index < 0 or index >= size:
        return None
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return None
        if fn % 2 == 1 or fn == sn:
            r = node_hash(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn //= 2
                    sn //= 2
        else:
            r = node_hash(r, p)
        fn //= 2
        sn //= 2
    return r if sn == 0 else None


def verify_receipt(data, published, statement=None):
    """Rebuild the leaf from the receipt, walk the inclusion proof to a root, check our ES256 signature over it."""
    try:
        prot_bytes, prot, unprot, _, sig = _sign1(data)
    except ValueError as e:
        return {"ok": False, "reason": "not a receipt: %s" % e}
    if prot.get(1) != -7 or prot.get(395) != 1 or prot.get("riskrouter-profile") != "riskrouter-scitt-receipt|1":
        return {"ok": False, "reason": "not an ES256 RFC9162_SHA256 riskrouter-scitt-receipt|1"}
    cwt, fields = prot.get(15) or {}, prot.get("riskrouter-leaf")
    digest = cwt.get(2)
    if not isinstance(digest, str) or not HEX64.match(digest) or not isinstance(fields, list) or len(fields) != 4:
        return {"ok": False, "reason": "the receipt does not carry the leaf it proves"}
    proofs = (unprot.get(396) or {}).get(-1) if isinstance(unprot, dict) else None
    if not isinstance(proofs, list) or len(proofs) != 1:
        return {"ok": False, "reason": "the receipt carries no single inclusion proof"}
    tree_size, proof_index, path = cbor_decode(proofs[0])
    leaf_index, created_at, distributor_id, kind = fields
    if proof_index != leaf_index:
        return {"ok": False, "reason": "the inclusion proof is for another leaf than the receipt names"}
    leaf = leaf_hash(leaf_string({"leaf_index": leaf_index, "created_at": created_at, "distributor_id": distributor_id,
                                  "kind": kind, "record_digest": digest}).encode("utf-8"))
    root = _root_from_path(leaf_index, tree_size, leaf, [p.hex() for p in path])
    if root is None:
        return {"ok": False, "reason": "the inclusion proof does not lead to a root"}
    key = pick_key(published, prot.get(4, b"").decode("utf-8", "replace"))
    if key is None:
        return {"ok": False, "reason": "signed with a key that is not among the keys you trust"}
    tbs = cbor_encode(["Signature1", prot_bytes, b"", bytes.fromhex(root)])
    if not ecdsa_p256_verify(key["public_key"], tbs, base64.b64encode(sig).decode("ascii")):
        return {"ok": False, "reason": "our signature over the root does not verify: the receipt was changed, or is not for this leaf"}
    if statement is not None and statement_digest(statement) != digest:
        return {"ok": False, "reason": "the receipt is for another statement"}
    return {"ok": True, "tree_size": tree_size, "leaf_index": leaf_index, "root_hash": root, "statement_digest": digest, "kind": kind}


def _cose_main(path, argv):
    with open(path, "rb") as fh:
        data = fh.read()
    key_path = _arg(argv, "--key")
    if not key_path:
        print("a receipt is checked against our published key: pass --key (a key file, or anchors/)", file=sys.stderr)
        return 2
    published = load_keyring(key_path)
    try:
        _, prot, unprot, _, _ = _sign1(data)
    except ValueError as e:
        print("FAIL  not a COSE_Sign1: %s" % e)
        return 1
    failed = False
    statement_path = _arg(argv, "--statement")
    if isinstance(unprot, dict) and 394 in unprot:
        results = [verify_receipt(r, published, data) for r in unprot[394]]   # a Transparent Statement
    else:
        stmt = open(statement_path, "rb").read() if statement_path else None
        results = [verify_receipt(data, published, stmt)]
    for r in results:
        print(("OK    statement %s is leaf %d in a tree of %d leaves with root %s; we signed that root"
               % (r["statement_digest"], r["leaf_index"], r["tree_size"], r["root_hash"])) if r["ok"] else "FAIL  " + r["reason"])
        failed = failed or not r["ok"]
    return 1 if failed else 0


# ----------------------------------------------------------------- self-test

def self_test():
    """RFC 6962 reference roots, and one known ECDSA P-256 signature."""
    leaves = [leaf_hash(bytes.fromhex(h)) for h in
              ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]]
    roots = ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
             "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
             "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
             "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
             "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
             "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
             "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
             "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"]
    for n in range(1, 9):
        assert root_hash(leaves[:n]) == roots[n - 1], "RFC 6962 root %d" % n
    assert root_hash([]) == EMPTY_ROOT
    assert _on_curve(G)
    # RFC 8032, section 7.1, test 2: one byte, and the same byte changed.
    pub = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    sig = bytes.fromhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
    assert ed25519_verify(pub, bytes([0x72]), sig)
    assert not ed25519_verify(pub, bytes([0x73]), sig)
    return True


# ---------------------------------------------------------------------- CLI

def _arg(argv, name):
    if name in argv:
        i = argv.index(name)
        if i + 1 < len(argv):
            return argv[i + 1]
    return None


def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _args(argv, name):
    return [argv[i + 1] for i, a in enumerate(argv) if a == name and i + 1 < len(argv)]


def _vkey(value):
    return open(value, "r", encoding="utf-8").read().strip() if os.path.isfile(value) else value.strip()


def _checkpoint_main(path, argv):
    """A C2SP checkpoint note; beside checkpoint.txt, any *.cosignature lines are read too."""
    with open(path, "r", encoding="utf-8") as fh:
        note = fh.read()
    if os.path.basename(path) == "checkpoint.txt":
        folder = os.path.dirname(path) or "."
        for f in sorted(os.listdir(folder)):
            if f.endswith(".cosignature"):
                with open(os.path.join(folder, f), "r", encoding="utf-8") as fh:
                    note += fh.read()
    vkey = _arg(argv, "--vkey")
    if not vkey:
        print("a checkpoint is checked against the log's published key: pass --vkey (the vkey, or a file holding it)", file=sys.stderr)
        return 2
    failed = False
    for ok, line in verify_checkpoint(note, _vkey(vkey), [_vkey(v) for v in _args(argv, "--witness-vkey")]):
        print(("OK    " if ok else "FAIL  ") + line)
        failed = failed or not ok
    return 1 if failed else 0


def main(argv):
    if "--self-test" in argv:
        self_test()
        print("OK    RFC 6962 reference roots, the P-256 curve and RFC 8032 Ed25519 check out")
        return 0
    files = [a for i, a in enumerate(argv) if not a.startswith("--") and (i == 0 or not argv[i - 1].startswith("--"))]
    if not files:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    with open(files[0], "rb") as fh:
        if fh.read(1) == b"\xd2":        # a tagged COSE_Sign1: a receipt or a Transparent Statement
            return _cose_main(files[0], argv)
    with open(files[0], "r", encoding="utf-8") as fh:
        head = fh.read(4096)
    if not head.lstrip().startswith(("{", "[")) and "\n\n\u2014 " in open(files[0], "r", encoding="utf-8").read():
        return _checkpoint_main(files[0], argv)
    doc = _load(files[0])
    key_path = _arg(argv, "--key")
    published = load_keyring(key_path) if key_path else None
    fmt = doc.get("format", "") if isinstance(doc, dict) else ""
    failed = False

    def report(ok, line):
        nonlocal failed
        print(("OK    " if ok else "FAIL  ") + line)
        failed = failed or not ok

    if isinstance(doc, list):
        r = verify_rows(doc)
        report(r["intact"], "%d entries, each rebuilt from its content; head %s" % (r["checked"], r["head_hash"]) if r["intact"]
               else "broken at entry %s: %s" % (r.get("broken_at"), r["reason"]))
    elif fmt.startswith("riskrouter-ledger-export|"):
        r = verify_export(doc)
        report(r["intact"], "%d links to the head; %d of your entries rebuilt from content, the rest followed by digest only"
               % (r["checked"], r["proved"]) if r["intact"] else "broken at entry %s: %s" % (r.get("broken_at"), r["reason"]))
    elif fmt == "riskrouter-entry-proof|v1":
        r = verify_entry_proof(doc)
        report(r["intact"], "entry %d rebuilt from its content; %d links to the head, followed by digest only"
               % (r["index"], r["links"]) if r["intact"] else "broken at %s: %s" % (r.get("broken_at"), r["reason"]))
    elif fmt == "riskrouter-evidence-proof|v2":
        saved = _arg(argv, "--saved-head")
        signer = _arg(argv, "--signer-key")
        r = verify_evidence_proof(doc, _load(saved).get("head", _load(saved)) if saved else None, _load(signer) if signer else None)
        report(r["intact"], "entry %d is in the tree of %d leaves with root %s" % (r["leaf_index"], r["tree_size"], r["root_hash"])
               if r["intact"] else r["reason"])
        if r["intact"] and r.get("signer_key_id"):
            report(True, "the signer %s asserted this claim at %s; its own signature verifies%s"
                   % (r["signer_key_id"], r["claimed_at"], " against the key you supplied" if signer else " against the key the proof carries"))
        if published is not None and not saved and doc.get("head"):
            s = verify_head_signature(doc["head"], doc.get("signature"), published)
            report(s["ok"], "we signed that head" if s["ok"] else s["reason"])
    elif fmt == "riskrouter-evidence-consistency|v2":
        saved = _arg(argv, "--saved-head")
        if not saved:
            print("a consistency proof is checked against a head YOU saved: pass --saved-head", file=sys.stderr)
            return 2
        saved_doc = _load(saved)
        r = verify_consistency_doc(doc, saved_doc.get("head", saved_doc))
        report(r["intact"], "the head of %d leaves you saved is a prefix of the head of %d" % (r["first"], r["second"])
               if r["intact"] else r["reason"])
        if published is not None:
            s = verify_head_signature(doc["head"], doc.get("signature"), published)
            report(s["ok"], "we signed the current head" if s["ok"] else s["reason"])
    elif fmt == "riskrouter-evidence-cosignature|v2":
        wk = _arg(argv, "--witness-key")
        if not wk:
            print("a cosignature is checked against the witness's own published key: pass --witness-key", file=sys.stderr)
            return 2
        r = verify_cosignature(doc, _load(wk), published)
        report(r["ok"], "witnessed tree_size %s, root %s" % (r["tree_size"], r["root_hash"]) if r["ok"] else r["reason"])
    elif fmt == "riskrouter-head-timestamp|1":
        for ok, line in verify_head_timestamp(doc, published):
            if ok is None:
                print("NOTE  " + line)
            else:
                report(ok, line)
    elif fmt == "riskrouter-record-bundle|1":
        for ok, line in verify_record_bundle(doc, published):
            report(ok, line)
    elif fmt in ("riskrouter-disclosure-bundle|1", "riskrouter-evidence-chain|v1", "riskrouter-completeness-bundle|1",
                 "riskrouter-spot-check-bundle|1", "riskrouter-coseal|1"):
        check = {"riskrouter-disclosure-bundle|1": verify_disclosure,
                 "riskrouter-evidence-chain|v1": lambda d, p: verify_chain_statement(d, p)[0],
                 "riskrouter-completeness-bundle|1": check_completeness,
                 "riskrouter-spot-check-bundle|1": check_spot_check,
                 "riskrouter-coseal|1": verify_coseal}[fmt]
        for ok, line in check(doc, published):
            if ok is None:
                print("NOTE  " + line)
            else:
                report(ok, line)
    elif isinstance(doc, dict) and doc.get("attestation") and doc.get("signature"):
        if published is None:
            print("an attestation is checked against a published key: pass --key", file=sys.stderr)
            return 2
        r = verify_attestation_signature(doc, published)
        report(r["ok"], "we signed head %s over %s entries" % (doc["attestation"].get("head_hash"), doc["attestation"].get("entries"))
               if r["ok"] else r["reason"])
    else:
        print("not a file this verifier recognises", file=sys.stderr)
        return 2

    if published is not None and (fmt.startswith("riskrouter-ledger-export|") or fmt == "riskrouter-entry-proof|v1"):
        s = verify_attestation_signature(doc, published)
        report(s["ok"], "we signed the head it links to" if s["ok"] else s["reason"])
    expect = _arg(argv, "--expect-head")
    if expect and fmt.startswith("riskrouter-ledger-export|"):
        r = verify_export(doc)
        at = position_of_head(doc, expect) if r.get("intact") else None
        if at is None:
            report(False, "the head you recorded earlier is NOT in this chain: history changed, this is another ledger, "
                          "or the head is newer than this file")
        elif at == r["checked"]:
            report(True, "matches the head you recorded earlier: history is unchanged")
        else:
            report(True, "the head you recorded earlier was the head after entry %d: history up to it is unchanged, "
                         "%d added since" % (at, r["checked"] - at))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
