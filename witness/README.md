# Run a witness

A witness checks that an evidence log never rewrites history. Each hour it takes the log's current
signed head, checks a consistency proof against the head it saved last time, and co-signs only if
the log grew without changing anything that came before. If the log contradicts a head it saw, the
witness keeps both signed heads, publishes them as an alarm, and stops co-signing that log for good.

It is worth something because it is not the log's operator. So it runs on **your** account, with a
key **you** generate and nobody else ever sees. Design: `docs/witness-network.md` in the RiskRouter
repository; the cosignature format is in the specification at <https://riskrouter.eu/spec#witnesses>.

## Files

| File | What it is |
| --- | --- |
| `core.mjs` | One witnessing round for many logs. WebCrypto only; runs on Workers, Node and Actions. |
| `worker.js` | The witness as a Cloudflare Worker (hourly Cron Trigger, state in KV). |
| `wrangler.toml.example` | Its configuration. |
| `node.mjs` | The witness as a command: `init` makes the key, `run` does a round into a directory. |
| `github-workflow.yml` | The witness in GitHub Actions, in a fork of the verifier repository. |
| `config.example.json` | Which logs to witness: the public registry, and any you name yourself. |

`core.mjs` needs `../tools/merkle.mjs`, which sits beside it in the verifier repository.

## 1. Make a key

```bash
node witness/node.mjs init --out ./my-witness --name "Your organisation"
```

- `./my-witness/private-key.b64` is the private key. Put it in a secret store. Never commit it.
- `./my-witness/public-key.json` is what you publish, on a site you control, and send to be listed.

## 2. Run it, one of three ways

**Cloudflare Worker.** See the top of `wrangler.toml.example`: create a KV namespace, add the key
with `wrangler secret put WITNESS_PRIVATE_KEY`, deploy. It serves, read-only:

```
/public-key.json                  your public key
/logs.json                        the logs it witnesses, and how the last round went
/cosignatures/<log>/latest.json   its latest cosignature of each log
/alarms/<log>.json                the evidence, if a log was caught rewriting history
```

**GitHub fork.** See the top of `github-workflow.yml`. Your cosignatures are committed hourly to
`witness-state/` in your fork.

**Your own server.**

```bash
WITNESS_PRIVATE_KEY="$(cat ./my-witness/private-key.b64)" \
  node witness/node.mjs run --config witness.config.json --state ./state --every 3600 --port 8080
```

A self-hosted RiskRouter stack has it built in: `docker compose ... --profile witness up -d`.

`run` without `--every` does one round and exits 0 when all is well, 2 when an alarm stands for any
log, and 1 when no log could be co-signed.

## 3. Get listed

Send your `public-key.json`, the https address where you publish the same key, and (optionally) the
address your witness serves from, through <https://riskrouter.eu/contact>. You are listed in
<https://riskrouter.eu/registry.json> and on <https://riskrouter.eu/witnesses>; a daily job collects
your latest cosignature of our log and keeps it if it verifies.

## Why it pins keys

Following the registry is a convenience. The first time the witness sees a log it pins that log's
keys, and from then on it accepts an added key (a rotation) but never a dropped or changed one: a
registry that could swap a key could make a witness co-sign a forged history. A registry may also
never point a witness at a private address; only you can configure one.

## What a cosignature proves

That you saw that head and checked it was consistent with every head you saw before. Nothing about
the records behind it, and nothing about the time after your witness stops running.
