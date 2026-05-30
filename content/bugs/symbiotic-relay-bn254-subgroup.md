---
title: "Symbiotic Relay `KeyBlsBn254` accepts non-subgroup points"
category: input-validation
subcategory: "Curve Points Not Validated"
order: 1
date: 2025-07-01
primitives: [elliptic-curve, signature]
repository: https://github.com/sherlock-audit/2025-06-symbiotic-relay
source:
  - name: "Sherlock #98"
    url: https://github.com/sherlock-audit/2025-06-symbiotic-relay-judging/issues/98
  - name: "Sherlock #76"
    url: https://github.com/sherlock-audit/2025-06-symbiotic-relay-judging/issues/76
hidden: true
---

In Symbiotic Relay's middleware SDK, `KeyBlsBn254.wrap()` validates an incoming
BN254 G1 point as a validator BLS public key. It rejects the zero point, checks
that both coordinates lie in $[0, p)$, then derives $Y$ from $X$ via the curve
equation and confirms membership. It then stops, with no subgroup-membership
check ([source](https://github.com/sherlock-audit/2025-06-symbiotic-relay/blob/main/middleware-sdk/src/contracts/libraries/keys/KeyBlsBn254.sol#L17-L34)):

```solidity
// FILE: middleware-sdk/src/contracts/libraries/keys/KeyBlsBn254.sol
// sherlock-audit/2025-06-symbiotic-relay (vulnerable)
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
    // MISSING: subgroup check, cofactor*keyRaw should equal point at infinity
    key = KEY_BLS_BN254(keyRaw);
}
```

BN254 has cofactor $h > 1$, so the curve contains small-order points outside
the prime-order subgroup. An attacker registers such a point as their validator
key; every subsequent BLS aggregation that includes it operates outside the
subgroup the security proof assumes, and the pairing equation becomes
satisfiable for crafted signatures without knowledge of the corresponding
private key. 

The same omission appears on the verification side
([Sherlock #76](https://github.com/sherlock-audit/2025-06-symbiotic-relay-judging/issues/76))
in `SigBlsBn254.verify()`, which decodes attacker-controlled G1 and G2 points
from calldata and feeds them straight into `BN254.safePairing(...)` without
checking either is in its respective subgroup.

The audit's recommended fix is the standard `cofactor*P == 0`
check before storing the key.
