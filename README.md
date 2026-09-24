# riskrouter-verify

Independent, offline verification for [RiskRouter](https://riskrouter.eu)'s audit ledger — the
tamper-evident record of every insurance quote it prices. See
[riskrouter.eu/trust](https://riskrouter.eu/trust) for the full argument this repository exists to
back up. This repository holds nothing but the verification tools and the published proof
material. It is separate from RiskRouter's own (private) application repository on purpose: the
whole point of an independent verifier is that it does not depend on RiskRouter staying
operational, staying honest, or staying in business.

**If RiskRouter disappears tomorrow, this repository still lets you prove what it told you.**

## Why this exists

Under the EU's Insurance Distribution Directive (IDD), Article 20 requires a distributor to
document what a customer needed and justify what was recommended. A database that allows edits or
deletions cannot make that proof — a regulator has no way to tell an accurate history from a
corrected one. RiskRouter seals every quote into a SHA-256 hash chain server-side, so changing one
entry breaks every entry after it.

A hash chain alone proves history was not *edited*. It cannot prove history was not *rebuilt*,
because a rebuild recomputes every digest consistently and looks perfect. Two things close that
gap, and both are here:

1. **A signed attestation.** RiskRouter periodically signs its current head hash with an ECDSA
   P-256 key and publishes it. A saved attestation is something they cannot later disown.
2. **A copy nobody but you controls.** This repository — and the periodic third-party Bitcoin
   timestamps committed to `anchors/` — exist outside RiskRouter's own infrastructure. Even if
   their private repository, their database, or the company itself were gone or compromised, the
   verification logic and the published proofs here are not.

None of the three scripts below share a single line of code with the server that produces the
ledger or the signature. They read a file you already have and a public key you already have, and
they contact nothing. Agreement between the two is evidence; it would not be if they were the same
code checking itself.

## What's here

```
tools/verify-ledger.mjs        rebuilds every digest in a ledger export and follows the chain;
                               --expect-head checks a head you saved earlier is still in it
tools/verify-attestation.mjs   checks a saved attestation's signature against the published keys
tools/entry-proof.mjs          cuts a single-entry proof from an export, to show one quote only
tools/keyring.mjs              picks the published key by its id, so old attestations keep verifying
tools/verify-anchors.mjs       checks a ledger against every attestation RiskRouter has published
anchors/                       the public key, and every attestation and timestamp proof so far
```

Each script is plain Node.js — no dependencies, nothing to `npm install`. Run any of them with
`node <path> --help`-style usage shown by running it with no arguments.

## Quick start

```bash
git clone https://github.com/aniljangrabe-dev/riskrouter-verify
cd riskrouter-verify

# Check the attestation already published in this repository:
node tools/verify-attestation.mjs anchors/attestation-2026-09-13.json

# Pull your own export and check it against everything RiskRouter has ever attested to:
curl -H "Authorization: Bearer $RISKROUTER_API_KEY" \
  https://api.riskrouter.eu/api/v1/ledger/export > my-export.json
node tools/verify-ledger.mjs my-export.json
node tools/verify-anchors.mjs my-export.json
```

See `anchors/README.md` for what each check actually proves, what it does not, and the exact
steps to take today so you hold your own proof independently of RiskRouter continuing to publish
one.

## What this is not

This is not RiskRouter's application. It contains no pricing logic, no database schema, and no
credentials of any kind — nothing here could price a quote or write to anyone's ledger even if it
tried. It is the read-only half of the system, published separately so that half of the promise
("verify without us") does not itself depend on trusting the half that stayed private.

## License

MIT — see `LICENSE`. Fork it, vendor it into your own compliance tooling, or point a regulator at
it directly.
