---
title: "WSTS threshold-raise via oversized polynomial"
category: input-validation
subcategory: "Received Sequence Has the Wrong Length"
date: 2024-10-01
primitives: [secret-sharing, commitment]
repository: https://github.com/Trust-Machines/wsts
issue: 87
pr: 88
hidden: false
---

WSTS (Weighted Schnorr Threshold Signatures), aka WileyProofs, is based on [FROST](https://eprint.iacr.org/2020/852.pdf) and was vulnerable to threshold-raise attacks. Before PR #88, the per-signer DKG verification in `src/v1.rs` only checked the Schnorr ID, not the commitment-vector length
([source](https://github.com/Trust-Machines/wsts/blob/v9.1.0/src/v1.rs#L154-L157)):

```rust
// src/v1.rs — Trust-Machines/wsts (vulnerable, before PR #88)
if !comm.verify() {
    bad_ids.push(*i);
}
self.group_key += comm.poly[0];
```

A malicious signer could append commitments to its `poly` to silently raise the
reconstruction threshold. The [Trail of Bits length-check fix](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/) in `Trust-Machines/wsts` landed as [PR #88](https://github.com/Trust-Machines/wsts/pull/88) ("Check length of polynomials"). PR #88 added the explicit
equality check at every DKG verification site
([source](https://github.com/Trust-Machines/wsts/blob/v9.2.0/src/v1.rs#L155-L159)):

```rust
// src/v1.rs — Trust-Machines/wsts (fixed, PR #88)
if comm.poly.len() != threshold || !comm.verify() {
    bad_ids.push(*i);
} else {
    self.group_key += comm.poly[0];
}
```
