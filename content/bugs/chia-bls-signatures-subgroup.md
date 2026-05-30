---
title: "Chia `bls-signatures` `G1Element::CheckValid` missing subgroup check"
category: input-validation
subcategory: "Curve Points Not Validated"
order: 3
date: 2021-09-08
primitives: [elliptic-curve, signature]
repository: https://github.com/Chia-Network/bls-signatures
issue: 271
source:
  - name: "Chia bls-signatures Issue #271"
    url: https://github.com/Chia-Network/bls-signatures/issues/271
  - name: "Fix commit (Relic submodule bump)"
    url: https://github.com/Chia-Network/bls-signatures/commit/a5f420c193e14d20f972c0fd5110708c696de074
hidden: true
---

Chia's `bls-signatures` library over BLS12-381 validated incoming G1 public keys via `G1Element::CheckValid`, which confirmed the on-curve equation but performed no subgroup-membership check. BLS12-381 G1 has cofactor $h > 1$, so the curve contains small-order points outside the prime-order subgroup. A concrete G1 point that satisfies the curve equation but lies outside the subgroup was reported as a witness ([source](https://github.com/Chia-Network/bls-signatures/issues/271)):

```text
X: 1850443652098619803069679949935703490545934817616361671487073351271435645926537537028144222559542259604367871156773
Y: 1776970151258755586951871078535415548807448204545244204542330019247278385570277860229537378843413568111354158837149
```

A non-subgroup public key satisfies the pairing equation for crafted signatures without knowledge of the corresponding private key, giving signature forgery; the same omission also breaks the soundness of any BLS aggregation that combines such a key into the joint public key.

The issue was resolved via a [Relic submodule bump](https://github.com/Chia-Network/bls-signatures/commit/a5f420c193e14d20f972c0fd5110708c696de074) that added the missing subgroup check in the upstream pairing library rather than patching `CheckValid` directly in this repo.
