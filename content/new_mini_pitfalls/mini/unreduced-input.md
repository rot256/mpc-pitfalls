---
title: "Input not reduced to the arithmetic domain"
class: "Input Validation"
source: "improper-input-checks.md"
---

### Input not reduced to the arithmetic domain

**What can go wrong.** When a protocol's arithmetic domain is $\mathbb{Z}_q$ (or
$\mathbb{Z}_{2^k}$, or any modular ring), an incoming bitstring is untyped — it can encode
a raw integer $x$ outside the modulus. If the protocol accepts $x$ verbatim without
reducing modulo $q$ or range-checking against $q$, two byte-distinct wire values $x$ and
$x + q$ represent the same algebraic element. Downstream consumers that see only the raw
bytes then treat them as different inputs. Protocols claiming malicious security carry a
specific obligation here: every party's input must be checked or proven well-formed
*before* it enters the authenticated state.

**Security implication.** A malicious orchestrator submits $m' = m + q$ (or any
$m' \equiv m \pmod{q}$ with $m' \ne m$). All parties compute the same signature, MAC, or
commitment for $m'$ as for $m$, but an external verifier treating the raw bytes as the
signed message accepts both as valid signatures — breaking single-signature-per-message
unforgeability. More broadly, unvalidated out-of-domain inputs produce correctness
violations (silent modular wrap-around that parties accept as correct output) or privacy
violations (biased reconstructions that leak one bit of an honest party's input per
session).

**How to avoid.** Reject inputs at the protocol boundary: before accepting any bitstring
as a domain element, verify its integer value lies in $[0, q)$ (or the ring-appropriate
range). A single `value.Cmp(modulus) < 0` check at every entry point is usually
sufficient.

**Example: tss-lib ECDSA signing accepts messages $\ge q$ ([Issue #55](https://github.com/bnb-chain/tss-lib/issues/55), finding KS-BTL-F-01).** In
`bnb-chain/tss-lib` before October 2019, the round-1 signing entry-point used the input
message `round.temp.m` without checking it lay in $[0, q)$. The developers had even left
a TODO comment naming the missing check
([source](https://github.com/bnb-chain/tss-lib/blob/38d1b436e7b8d08dc8390073188e4e6a1b63d999/ecdsa/signing/round_1.go#L29-L40)):

```go
// FILE: ecdsa/signing/round_1.go — bnb-chain/tss-lib (vulnerable, before commit b611d95)
// missing:
// line1: m = H(M) belongs to Zq
func (round *round1) Start() *tss.Error {
    if round.started {
        return round.WrapError(errors.New("round already started"))
    }
    round.number = 1
    round.started = true
    round.resetOK()

    k := common.GetRandomPositiveInt(tss.EC().Params().N)
    // ... round.temp.m is used downstream without a Z_q check
}
```

A malicious orchestrator submits $m' = m + q$. All parties compute a signature for $m'$
but the bytes of $m'$ differ from $m$; an external verifier treating the raw bytes as
the signed message accepts both as valid signatures. The fix
([commit `b611d95`](https://github.com/bnb-chain/tss-lib/commit/b611d95e75e7ac8aeadd61fd37c03396f0ea02f3),
October 8, 2019) added an explicit range check at the start of round 1:

```go
// FILE: ecdsa/signing/round_1.go — bnb-chain/tss-lib (fixed, KS-BTL-F-01)
if round.temp.m.Cmp(tss.EC().Params().N) >= 0 {
    return round.WrapError(errors.New("hashed message is not valid"))
}
```
