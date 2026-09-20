# Anchors

A hash chain proves that history has not been *edited*. It cannot prove that history was not
*rebuilt*, because a rebuild recomputes every digest consistently and the result looks perfect.

The only defence is that somebody recorded an earlier head hash *before* the rebuild could have
happened — and that record has to live somewhere the operator cannot quietly edit. This repository
is that somewhere. It is a separate, public clone from RiskRouter's own private one, held by nobody
who could be pressured, bribed, or compelled into silently rewriting both copies to match.

## What is here

| File | What it is |
| --- | --- |
| `signing-key.json` | The public half of RiskRouter's attestation key. Published here so it can be checked without asking them. |
| `attestation-*.json` | Signed attestations, each committed on the date it was taken. |
| `attestation-*.json.<calendar>.ots` | Third-party timestamp proofs for that attestation — see below. |

## Two different jobs

**Non-repudiation** — closed. Every attestation from `GET /api/v1/ledger/attestation` is signed with
ECDSA P-256 over a fixed payload:

```
riskrouter-ledger-attestation|v1|<as_of>|<entries>|<head_hash>
```

A saved attestation is therefore something RiskRouter cannot disown. Check one with:

```bash
node tools/verify-attestation.mjs anchors/attestation-2026-09-13.json
```

The verifier shares no code with the server that produced the signature and contacts nothing.

**Distribution** — partly. Committing attestations here puts them somewhere with a timestamp nobody
at RiskRouter writes, and anyone who clones this repository holds a copy they cannot reach. Be
precise about the limit: this file could still, in principle, be force-pushed here and rewritten by
whoever holds write access to this repository. What cannot be undone is a copy already in someone
else's clone — and a force-push here is visible to everyone who has one, which is the entire reason
this repository is separate from RiskRouter's own private one rather than a directory inside it.

**A third-party notary — mechanism built, checked as of the date below.** RiskRouter submits an
anchor's SHA-256 to OpenTimestamps calendar servers and commits the resulting `.ots` proof here.
That removes RiskRouter's own control from the distribution side entirely: the calendars are not
theirs, and Bitcoin is nobody's.

Read the state of an `.ots` file precisely, because there are three states and only the last one is
worth relying on:

| State | What it proves |
| --- | --- |
| No `.ots` file | Nothing beyond the operator's own timestamp, which is their own claim. |
| A fresh `.ots` | A calendar that is not RiskRouter's received this digest and undertook to include it. |
| An upgraded `.ots` | The digest existed before a specific Bitcoin block. |

`ots upgrade` moves the second state to the third, hours to days later, once a block confirms. A
fresh file is a submission, not a blockchain anchor, and saying otherwise would be exactly the
overclaim this repository exists to avoid.

```bash
ots verify anchors/attestation-<date>.json.opentimestamps-a.ots anchors/attestation-<date>.json
ots upgrade anchors/attestation-<date>.json.opentimestamps-a.ots
```

(`ots` is the reference [OpenTimestamps client](https://github.com/opentimestamps/opentimestamps-client).
It is optional: `tools/verify-anchors.mjs` reports which calendars a `.ots` names without it, and the
upgrade step is only needed if you want a fully offline check that the digest predates a specific
Bitcoin block.)

## Checking anchors against a ledger you hold

An anchor nobody compares to anything is a receipt in a drawer. The comparison is:

> for each anchored attestation (`entries = N`, `head = H`), the ledger's head after its first N
> entries must still be H.

```bash
node tools/verify-anchors.mjs export.json        # your own export from GET /api/v1/ledger/export
node tools/verify-anchors.mjs rows.json          # or raw rows, which rebuilds every digest from content
```

It reports `MATCH`, `MISMATCH` or `UNCHECKABLE` per anchor and exits non-zero on any problem.
Signatures are checked by spawning `tools/verify-attestation.mjs` — the same tool you would run by
hand — rather than reimplementing the check, because two copies of a signature verifier is two
chances to get it subtly wrong.

This catches the one forgery a hash chain alone cannot see. A rebuilt ledger is internally flawless
and `verify-ledger.mjs` will call it `INTACT`. It cannot reproduce a head anchored *before* the
rebuild — which is exactly what these files are for.

## If you are a distributor or an auditor, do this once

Do not rely on RiskRouter — or this repository, which they also control — staying honest on its own.

```bash
curl -H "Authorization: Bearer $RISKROUTER_API_KEY" \
  https://api.riskrouter.eu/api/v1/ledger/attestation > my-attestation.json
```

Keep that file somewhere RiskRouter cannot reach — your own machine, your own backup. It is signed,
so they cannot deny it, and it is yours, so they cannot alter it. Later, export your rows and check
that the history you are shown still produces the head hash you hold:

```bash
curl -H "Authorization: Bearer $RISKROUTER_API_KEY" \
  https://api.riskrouter.eu/api/v1/ledger/export > my-export.json
node tools/verify-ledger.mjs my-export.json --expect-head <head_hash from your saved attestation>
```

If those disagree, the ledger you are being shown is not the ledger that existed when you saved it.
There is no version of that sentence RiskRouter gets to explain away.

## Key rotation

If the signing key ever changes, the old public key stays in this directory. An attestation signed
in 2026 must remain checkable in 2031, and deleting the key that verifies it would be a quiet way of
withdrawing a commitment already made.
