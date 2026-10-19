# check-seed

Two offline-first tools for **BIP39 seed phrases**:

- `check-seed` — validate that phrases are well-formed BIP39 mnemonics. No network.
- `check-balances` — derive addresses locally and look up their Bitcoin balance
  across a pool of public Electrum servers, load-balanced.

> [!WARNING]
> A seed phrase **is** your wallet's private key. Anyone who reads one can drain
> the wallet. Run this on a machine you trust, and never commit `seeds.txt`
> (it is gitignored here — keep it that way).

## What "offline-first" means here

The seed phrase is never transmitted. Addresses are derived on your machine and
only the resulting **scripthashes** go out over the wire — a one-way SHA256 of
each output script. A server cannot get from that back to your pubkey, let alone
your key. The Electrum server protocol has no method that accepts key material.

What servers *do* learn: your IP address, and exactly which scripthashes you
query. That is the real leak, and it is why `--strategy` defaults to spreading
requests around instead of hammering one server.

## Install

Requires [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

## Part 1 — validating phrases

Copy the example file and put your own phrases in it, one per line:

```bash
cp seeds.example.txt seeds.txt
$EDITOR seeds.txt
```

```bash
uv run check-seed                # validate seeds.txt
uv run check-seed path/to/list.txt
```

```
   6  PASS  [12 words, 128 bits]  valid
   7  FAIL  [12 words]  checksum failed (typo, wrong word order, or wrong words)

7/11 valid (4 invalid)
```

Phrases are never printed by default — output says PASS or FAIL and nothing
else. See the flag table below.

Exit code is `0` when every phrase is valid, `1` when any is invalid, `2` on a
usage or file error.

## Part 2 — looking up balances

Needs a server list. Generate one (this fetches the canonical Electrum directory
and liveness-probes every endpoint, keeping the ones that answer):

```bash
uv run check-balances --refresh-servers      # writes servers.txt
```

Then:

```bash
uv run check-balances seeds.txt              # balance for every phrase
uv run check-balances --verify 3             # corroborate across 3 servers
```

```
line 6: BALANCED  0.42130000 BTC  [electrum.emzy.de:50002, ...]
      p2wpkh                0.42130000 BTC                      (2 funded of 9 scanned)
      p2sh-p2wpkh           0.00000000 BTC                      (0 funded of 3 scanned)
      p2pkh                 0.00000000 BTC                      (0 funded of 3 scanned)
      cross-check 3 servers: agree
      appended to success.txt
```

Balances are shown as **confirmed**, with any mempool amount called out
separately (`(+0.00010000 BTC unconfirmed)`). A freshly-sent transaction still in
the mempool is therefore visible immediately rather than looking empty.

Addresses are derived for BIP84 (native segwit), BIP49 (P2SH-P2WPKH) and BIP44
(legacy P2PKH) by default, each scanned until `--gap` consecutive unused
addresses are found.

You can also query an address directly, with no seed involved:

```bash
uv run check-balances -a bc1q... --verify 3
```

### Testnet

`--testnet` switches everything: derivation uses testnet coin type `1'`
(`44'/1'`, `49'/1'`, `84'/1'`) and addresses encode as `tb1…` / `m…` / `2…`, the
default seed file becomes `testnet-seeds.txt` and the server list
`servers-testnet.txt`.

```bash
uv run check-balances --testnet --refresh-servers   # build testnet server list
uv run check-balances --testnet                     # check testnet-seeds.txt
uv run check-balances --testnet -a tb1q... --verify 3
```

Testnet addresses and mainnet addresses are mutually rejected: passing a `bc1…`
address with `--testnet` fails loudly rather than silently querying the wrong
chain. Note the derived *keys* genuinely differ between networks (different coin
type), not just the address prefix — so a testnet address is not a re-encoded
mainnet address.

### The success log

Any phrase with a non-zero balance (confirmed or unconfirmed) is appended to
`success.txt` — appended, never truncated, so the file accumulates across runs.
Each entry gets a timestamped comment line:

```
# 2026-10-19T12:34:56Z testnet line 3 0.00150000 BTC [blockstream.info:143]
legal winner thank year wave sausage worth useful legal winner thank yellow
```

(The phrase shown is a public BIP39 test vector with no funds — not a real seed.)

Use `--no-success-file` to disable, or `--success-file PATH` to redirect.

> [!WARNING]
> `success.txt` contains seed phrases. It is gitignored, written with mode
> `0600`, and must never be committed or shared. Delete it once you are done.

### Load balancing

`--strategy` controls how scripthashes are spread across the pool:

| Strategy | Behaviour |
|---|---|
| `round-robin` *(default)* | Each request goes to the next healthy server. Also the best privacy default — no single operator sees your whole address set. |
| `fastest` | Always prefer the lowest measured latency. Fastest, but concentrates your queries on one operator. |
| `random` | Uniform random pick per request. |
| `failover` | Pin to the first server, move on only when it fails. |

Servers that fail get an exponential cooldown (5s doubling, capped at 5 min) and
are skipped while unhealthy. `uv run check-balances --probe` shows liveness, and
`--stats` prints per-server health after a run.

### Speed

Addresses are queried concurrently over **pipelined, keep-alive connections**:

- one TCP+TLS connection per worker, reused for that worker's whole shard, instead
  of a fresh handshake per address;
- all requests for a shard written at once, then all replies read — one round-trip
  instead of one per address;
- all three script types queried in the same round, rather than three separate
  sequential passes;
- `--verify N` asks its N servers in parallel.

`--workers N` (default 8) sets how many connections are opened. One representative
testnet scan went from ~50s to ~5s without changing which addresses were checked.
Past `--workers 8` the returns are small and you start hitting the slowest server
in the pool; `--workers 2`–`4` is often just as quick because it avoids them
entirely.

### Trusting the numbers

**The balance comes from the server, not from your node.** A hostile or broken
server can report whatever it likes. Two mitigations:

1. `--verify N` recomputes the total from N *independent* servers and fails loudly
   on disagreement. This is a useful signal, not a guarantee — colluding or
   identically-wrong servers will still agree with each other.
2. For real assurance, run your own fulcrum/ElectrumX against your own Bitcoin
   Core node. Nothing short of validating the chain yourself removes the trust
   assumption.

Also note TLS here gives **encryption but not identity**: Electrum servers
routinely present self-signed certificates, and this tool does not pin them, so a
hostile server can still intercept traffic. Pinning is not implemented.

## Options

`check-seed`:

| Flag | Effect |
|---|---|
| `-q`, `--quiet` | Print only the `valid/total` summary line |
| `--preview` | Show first and last two words, eliding the middle |
| `--fingerprint` | Show a stable non-reversible id per phrase (safe to share) |
| `--reveal` | Print full text of **valid** phrases only (dangerous) |
| `--quiet-ok` | Suppress the startup warning banner |

`check-balances`:

| Flag | Effect |
|---|---|
| `-s`, `--servers` | Server list path (default `servers.txt`) |
| `--testnet` | Use testnet derivation and `servers-testnet.txt` |
| `-a`, `--address` | Check an address directly; repeatable |
| `-t`, `--script-type` | `p2wpkh`, `p2sh-p2wpkh`, `p2pkh`, or `all` (default) |
| `-n`, `--count` | Max addresses per script type (default 20) |
| `-g`, `--gap` | Stop after N consecutive unused (default 6) |
| `--strategy` | Load-balancing strategy (default `round-robin`) |
| `--workers N` | Concurrent connections (default 8) |
| `--verify N` | Corroborate the total across N independent servers |
| `--success-file` | Where to append funded phrases (default `success.txt`) |
| `--no-success-file` | Do not record funded phrases |
| `--probe` | Only test which servers are reachable |
| `--refresh-servers` | Regenerate the server list from the canonical directory |
| `--stats` | Print per-server health after the run |

## `servers.txt` format

```
# comments and blank lines ignored
electrum.emzy.de:50002:ssl
btc.electroncash.dk:60001:tcp
```

`host:port:ssl` or `host:port:tcp`. Omitting the suffix means TLS, except port
`50001`, which defaults to plaintext — matching Electrum's own convention.

## Library use

```python
from check_seed import check_mnemonic

valid, count, reason, entropy_bits = check_mnemonic(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
# (True, 12, 'valid', 128)
```

## What a valid phrase does and does not mean

A `PASS` means the phrase is a well-formed BIP39 mnemonic. It does **not** mean:

- the phrase is yours, or that it is the one for a given account;
- the wallet holding it still exists or has balance;
- the phrase is safe to store in a file (it usually isn't).

Checksum failures are the common case for a genuine typo, and a checksum pass
with wrong words is still a different wallet — BIP39 offers no way to detect
that offline.

## Development

```bash
uv run pytest                                     # 69 tests, no network needed
uv run check-seed seeds.example.txt               # public BIP39 test vectors
```

Tests use only public BIP39/BIP44/49/84 test vectors (mainnet *and* testnet) and a
local fake Electrum server bound to `127.0.0.1` — including one that lies about a
balance, to prove cross-checking catches it.

## License

No license file is included, so the default copyright applies. Add one (MIT,
Apache-2.0, …) before relying on this beyond personal use.