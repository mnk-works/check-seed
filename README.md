# check-seed

Offline validator for **BIP39 seed phrases**.

Reads a list of phrases from a text file and reports whether each one is a
structurally valid BIP39 mnemonic — wordlist membership, word count, and
checksum. Nothing is sent anywhere; the tool makes no network calls, derives no
keys, and never checks whether a phrase holds funds.

> [!WARNING]
> A seed phrase **is** your wallet's private key. Anyone who reads one can drain
> the wallet. Run this offline on a machine you trust, and never commit
> `seeds.txt` (it is gitignored here — keep it that way).

## Why output is redacted

The default output tells you *whether* a phrase is valid without ever printing
it. Terminal scrollback, screen shares, log files, and CI output are all places
a phrase can leak, so the tool assumes it is being watched.

```
$ check-seed seeds.txt

   6  PASS  [12 words, 128 bits]  valid
   7  FAIL  [12 words]  checksum failed (typo, wrong word order, or wrong words)

7/11 valid (4 invalid)
```

## Install

Requires [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

## Usage

Copy the example file and put your own phrases in it, one per line:

```bash
cp seeds.example.txt seeds.txt
$EDITOR seeds.txt
```

Then:

```bash
uv run check-seed                # validate seeds.txt
uv run check-seed path/to/list.txt
```

Exit code is `0` when every phrase is valid, `1` when any is invalid, `2` on a
usage or file error — so it drops straight into a shell pipeline.

### Options

| Flag | Effect |
|---|---|
| `-q`, `--quiet` | Print only the `valid/total` summary line |
| `--preview` | Show first and last two words, eliding the middle |
| `--fingerprint` | Show a stable non-reversible id per phrase (safe to share) |
| `--reveal` | Print full text of **valid** phrases only (dangerous) |
| `--quiet-ok` | Suppress the startup warning banner |

`--fingerprint` exists for support and reconciliation workflows: the same phrase
always maps to the same 16-hex id, but the id cannot be walked back to the
phrase. Note that it is derived from the BIP39 seed, so a fingerprint is
sensitive if the phrase is a real one — treat it as pseudonymous, not anonymous.

## Library use

```python
from check_seed import check_mnemonic

valid, count, reason, entropy_bits = check_mnemonic(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
# (True, 12, 'valid', 128)
```

## What "valid" does and does not mean

A `PASS` means the phrase is a well-formed BIP39 mnemonic. It does **not** mean:

- the phrase is yours, or that it is the one for a given account;
- the wallet holding it still exists or has balance;
- the phrase is safe to store in a file (it usually isn't).

Checksum failures are the common case for a genuine typo, and a checksum pass
with wrong words is still a different wallet — BIP39 offers no way to detect
that offline.

## Development

```bash
uv run check-seed seeds.example.txt   # public BIP39 test vectors
uv run pytest
```

## License

No license file is included, so the default copyright applies. Add one (MIT,
Apache-2.0, …) before relying on this beyond personal use.