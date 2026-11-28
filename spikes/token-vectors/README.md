# Token vectors

`jws_vectors.py` builds the golden Episode Token and payment Call Proof that `src/tokens.rs`'s
tests pin, independently of the Rust code: pyca/cryptography (46.0.5 on 2026-11-04) signs with
deterministic RFC 6979 nonces, and the script normalizes `s` to low-S. The key is RFC 6979
A.2.5's P-256 test key; the script asserts its published `Ux`, and derives the RFC 7638 `kid`.
Header and claims are serialized with sorted keys and no whitespace, which equals JCS for
these ASCII-only members.

```bash
python3 -I jws_vectors.py   # prints KID, SEC1, EPISODE and PROOF
```
