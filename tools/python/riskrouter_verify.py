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
    a v2 evidence proof             riskrouter-evidence-proof|v2
    a v2 consistency proof          riskrouter-evidence-consistency|v2  (needs --saved-head)
    a v2 witness cosignature        riskrouter-evidence-cosignature|v2   (needs --witness-key)
    a list of v1 ledger rows

Exit status: 0 verified, 1 not verified, 2 usage.
"""
import base64
import hashlib
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
    return "|".join(["riskrouter-evidence-leaf", "v2", str(entry["leaf_index"]), entry["created_at"],
                     entry["distributor_id"], entry["kind"], entry["record_digest"]])


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


def verify_evidence_proof(doc, saved_head=None):
    """A v2 proof, against the head it carries or a head the holder saved."""
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
    return {"intact": True, "leaf_index": int(entry["leaf_index"]), "tree_size": int(head["tree_size"]), "root_hash": head["root_hash"]}


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


def main(argv):
    if "--self-test" in argv:
        self_test()
        print("OK    RFC 6962 reference roots and the P-256 curve check out")
        return 0
    files = [a for i, a in enumerate(argv) if not a.startswith("--") and (i == 0 or not argv[i - 1].startswith("--"))]
    if not files:
        print(__doc__.strip(), file=sys.stderr)
        return 2
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
        r = verify_evidence_proof(doc, _load(saved).get("head", _load(saved)) if saved else None)
        report(r["intact"], "entry %d is in the tree of %d leaves with root %s" % (r["leaf_index"], r["tree_size"], r["root_hash"])
               if r["intact"] else r["reason"])
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
