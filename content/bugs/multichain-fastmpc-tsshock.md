---
title: "Multichain fastMPC DLN `Iterations = 1` (TSSHOCK)"
date: 2022-12-12
primitives: [zkp]
repository: https://github.com/anyswap/FastMulThreshold-DSA
commit: 7727e4f833778c7ba847b3dce66e022595afad73
source:
  - name: "Verichains TSSHOCK report"
    url: https://verichains.io/tsshock/
---

Multichain's [`anyswap/FastMulThreshold-DSA`](https://github.com/anyswap/FastMulThreshold-DSA), a fork of `bnb-chain/tss-lib`, reduced the DLN proof iteration constant from thse spec-mandated 128 down to 1 in commit [`4e543437c6`](https://github.com/anyswap/FastMulThreshold-DSA/commit/4e543437c632e6ca709260d911c038f15e7663fc), collapsing the soundness margin to a coin flip per attempt ([source](https://github.com/anyswap/FastMulThreshold-DSA/blob/4e543437c632e6ca709260d911c038f15e7663fc/smpc-lib/crypto/ec2/ntildeZK.go#L22-L25)):
<!--more-->
```go
// FILE: smpc-lib/crypto/ec2/ntildeZK.go — anyswap/FastMulThreshold-DSA @ 4e543437 (vulnerable)
const (
    // Iterations iter times
    Iterations              = 1
)
```

Verichains demonstrated the [TSSHOCK c-guess attack](https://verichains.io/tsshock/) against this configuration: the adversary submits parallel signing requests, forges a valid DLN proof on roughly half of them, and uses the forged proof to extract a signing key share in a single signing ceremony.

The fix in commit [`7727e4f833`](https://github.com/anyswap/FastMulThreshold-DSA/commit/7727e4f833778c7ba847b3dce66e022595afad73) restored the constant ([source](https://github.com/anyswap/FastMulThreshold-DSA/blob/7727e4f833778c7ba847b3dce66e022595afad73/smpc-lib/crypto/ec2/ntildeZK.go#L22-L25)):

```go
// FILE: smpc-lib/crypto/ec2/ntildeZK.go — anyswap/FastMulThreshold-DSA @ 7727e4f8 (fixed)
const (
    // Iterations iter times
    Iterations              = 128
)
```
