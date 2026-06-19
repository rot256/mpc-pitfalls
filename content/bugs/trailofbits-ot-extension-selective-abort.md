---
title: "Trail of Bits: selective-abort leakage in OT-extension threshold ECDSA"
date: 2023-09-20
primitives: [oblivious-transfer, signature]
source:
  - name: "Trail of Bits, Don't overextend your Oblivious Transfer"
    url: https://blog.trailofbits.com/2023/09/20/dont-overextend-your-oblivious-transfer/
---

Trail of Bits disclosed a selective-abort vulnerability in an OT-based threshold-ECDSA
implementation in the Doerner et al. (DKLS) line. Whether the OT-extension consistency
check aborts is itself a function of the sender's secret choice bits, so a cheating
receiver learns "a few bits" per run from the pass/abort signal; because the base OTs
are reused, repeating it recovers every secret bit, and in a two-party setting the
nonce and the ECDSA signing key.

The fix is to "throw away the setup for a participant that has attempted to cheat
during the OT extension protocol."
