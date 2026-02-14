---
title: "Improper input checks"
class: "Protocol"
order: 12
---

It is often the case that the "secret space" differs from the "share space".
This is for example the case when using Shamir's secret sharing over a small field such as $\mathbb{F}_2$, or a ring such as $\mathbb{Z}_{2^{64}}$.
This is (arguably) also the case for protocols that rely on statistical hiding.
If the input mechanism of the secure protocol does not validate an input, it might lead to incorrect computations and/or breaches of privacy.
