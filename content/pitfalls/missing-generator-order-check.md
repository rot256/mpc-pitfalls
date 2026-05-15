---
title: "Subgroup-Generator Check Missing"
class: others
source: "improper-verification.md"
primitives: [elliptic-curve, signature]
---

### Subgroup-Generator Check Missing

<div class="pitfall-flags"><!--<span class="flag flag-tbd">TBD example</span>--><span class="flag flag-related">Closely related to <a href="#group-generator-not-validated">Group Generator Not Validated</a></span></div>

**What can go wrong.** A received value that is supposed to generate a non-trivial subgroup
must be checked to actually do so. At minimum, it must not be the identity (1 in a
multiplicative group, the point at infinity on a curve) and must have the expected order
(typically a large prime $q$). A received "generator" that equals 1 generates only the
trivial subgroup; a generator of order 2 or 4 on an RSA-style modulus leaks one or two bits
of any secret exponent per operation. Accepting an adversary-supplied generator without an
order check is the same mistake as accepting a zero field element, applied one level up the
algebraic hierarchy.

**Security implication.** A malicious party supplies a trivial or small-order generator as
its contribution to a shared protocol parameter, e.g. a Pedersen base, a DLN proof base or a
Paillier auxiliary generator. The honest verifier then uses it in exponentiations with its
own secret exponent, and each exponentiation leaks the low bits of that exponent. Across a
handful of rounds the attacker recovers the secret exponent completely, that is, a Pohlig–Hellman
decomposition in disguise.

**How to avoid.** Before using an adversary-supplied group element in any exponentiation,
verify it has the expected subgroup order. For example, on RSA-style moduli, check
$x^q \equiv 1 \pmod{N}$ and $x \notin \{1, N-1\}$; on non-prime-order curves, multiply by the
cofactor and reject the identity; on prime-order curves, reject the identity (point at
infinity).

<!--**Example.** *TBD on this page.* The concrete instances on this site live in the
[Discrete-Log Groups](../discrete-log-groups/) pitfall (generator validation; $g = \pm 1
\bmod p$ leaks the exponent LSB) and the [RSA / Paillier Moduli](../rsa-moduli/) pitfall
(missing DLN proofs for $h_1$, $h_2$ on Pedersen bases, CVE-2020-12118). Either is a worked
instance of this general failure.-->

**Example: Symbiotic Relay BLS key registration accepts non-subgroup points ([Sherlock #98](https://github.com/sherlock-audit/2025-06-symbiotic-relay-judging/issues/98)).**
In Symbiotic Relay's middleware SDK, `KeyBlsBn254.wrap()` validates an incoming BN254
G1 point as a validator BLS public key but only checks coordinate bounds and curve
membership ($y^2 \equiv x^3 + 3 \pmod p$); it does *not* check subgroup membership
([source](https://github.com/sherlock-audit/2025-06-symbiotic-relay/blob/main/middleware-sdk/src/contracts/libraries/keys/KeyBlsBn254.sol#L17-L34)):

```solidity
// middleware-sdk/src/contracts/libraries/keys/KeyBlsBn254.sol — Symbiotic Relay (vulnerable)
function wrap(
    BN254.G1Point memory keyRaw
) internal view returns (KEY_BLS_BN254 memory key) {
    if (keyRaw.X == 0 && keyRaw.Y == 0) {
        return zeroKey();
    }
    if (keyRaw.X >= BN254.FP_MODULUS || keyRaw.Y >= BN254.FP_MODULUS) {
        revert KeyBlsBn254_InvalidKey();
    }
    (uint256 beta, uint256 derivedY) = BN254.findYFromX(keyRaw.X);
    if (mulmod(derivedY, derivedY, BN254.FP_MODULUS) != beta) {
        revert KeyBlsBn254_InvalidKey();
    }
    if (keyRaw.Y != derivedY && keyRaw.Y != BN254.FP_MODULUS - derivedY) {
        revert KeyBlsBn254_InvalidKey();
    }
    // MISSING: subgroup check — cofactor·keyRaw should equal point at infinity
    key = KEY_BLS_BN254(keyRaw);
}
```

BN254 has cofactor $h > 1$, so the curve contains small-order points outside the
prime-order subgroup. An attacker registers such a point as their validator key; every
subsequent BLS aggregation that includes it operates outside the subgroup the security
proof assumes, and the pairing equation becomes satisfiable for crafted signatures
without knowledge of the corresponding private key. The audit's recommended fix is the
standard `cofactor·P == 0` check before storing the key.

<!--**Example: Symbiotic Relay BLS verification skips subgroup checks on calldata-supplied points ([Sherlock #76](https://github.com/sherlock-audit/2025-06-symbiotic-relay-judging/issues/76)).**
The same omission appears on the verification side. `SigBlsBn254.verify()` decodes
attacker-controlled `signatureG1` (G1) and `keyG2` (G2) from calldata and feeds them
directly into `BN254.safePairing(...)` with no subgroup-membership check on either point
([source](https://github.com/sherlock-audit/2025-06-symbiotic-relay/blob/main/middleware-sdk/src/contracts/libraries/sigs/SigBlsBn254.sol#L13-L42)):

```solidity
// middleware-sdk/src/contracts/libraries/sigs/SigBlsBn254.sol — Symbiotic Relay (vulnerable)
function verify(
    bytes memory keyBytes,
    bytes memory message,
    bytes memory signature,
    bytes memory extraData
) internal view returns (bool) {
    // ...
    BN254.G2Point memory keyG2 = abi.decode(extraData, (BN254.G2Point));
    BN254.G1Point memory signatureG1 = abi.decode(signature, (BN254.G1Point));
    // MISSING: subgroup checks on signatureG1 (G1) and keyG2 (G2) before pairing
    (bool success, bool result) = BN254.safePairing(
        signatureG1.plus(keyG1.scalar_mul(alpha)),
        BN254.negGeneratorG2(),
        messageG1.plus(BN254.generatorG1().scalar_mul(alpha)),
        keyG2,
        PAIRING_CHECK_GAS_LIMIT
    );
    return success && result;
}
```

The pairing equation is satisfiable by points that lie on the curve but outside the
prime-order subgroup, so an attacker can craft a `(signatureG1, keyG2)` pair that passes
`verify()` without knowing the corresponding private key — a complete signature-forgery
primitive against the consensus-layer authentication. The audit's recommended fix is
explicit `BN254.inG1Subgroup(signatureG1)` and `BN254.inG2Subgroup(keyG2)` calls before
the pairing, or renaming `verify` to `unsafeVerify` and pushing the obligation to
callers. Both Sherlock #98 and #76 were filed in the June 2025 contest and are open at
the time of writing.-->
