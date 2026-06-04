---
title: "Safeheron `multi-party-ecdsa-cpp` missing Paillier modulus validation"
date: 2023-07-30
primitives: [paillier, homomorphic-encryption, zkp]
repository: https://github.com/Safeheron/multi-party-ecdsa-cpp
pr: [7, 10]
source:
  - name: "POC"
    url: https://github.com/fireblocks-labs/safeheron-gg20-exploit-poc
cve:
  name: CVE-2023-33241
  url: https://nvd.nist.gov/vuln/detail/CVE-2023-33241
---

Safeheron's [`multi-party-ecdsa-cpp`](https://github.com/Safeheron/multi-party-ecdsa-cpp) ran GG18/GG20 key generation without checking the structure of each co-signer's Paillier modulus $N$, so a non-biprime or smooth $N$ flowed through keygen and into the GG20 signing rounds unchecked. One example of vulnerable code is the Round 3 keygen verifier ([pre-fix source](https://github.com/Safeheron/multi-party-ecdsa-cpp/blob/b75d125fa336f14d5ea2246b536994871c19215f/src/multi-party-ecdsa/gg18/key_gen/round3.cpp#L72-L75)):

```cpp
// FILE: src/multi-party-ecdsa/gg18/key_gen/round3.cpp
// Safeheron/multi-party-ecdsa-cpp @ b75d125f (pre-fix, vulnerable)
ok = bc_message_arr_[pos].pail_proof_.Verify(
    sign_key.remote_parties_[pos].pail_pub_,
    sign_key.remote_parties_[pos].index_,
    bc_message_arr_[pos].dlog_proof_x_.pk_.x(),
    bc_message_arr_[pos].dlog_proof_x_.pk_.y());
```

A malicious party could then publish $N = p_1 \cdots p_{16} \cdot q$ with each $p_i \approx 2^{16}$. During GG20 signing, the 16-factor structure opens parallel CRT channels and the small factors keep the MtA range-proof brute force at ~$2^{16}$ per channel. The victim's encrypted share $x$ leaks $x \bmod p_i$ per session; CRT reconstructs the full share over 16 to ~$10^9$ sessions ([Fireblocks technical report](https://www.fireblocks.com/blog/gg18-and-gg20-paillier-key-vulnerability-technical-report), [POC](https://github.com/fireblocks-labs/safeheron-gg20-exploit-poc)).

Safeheron's fix introduces two [CGGMP21](https://eprint.iacr.org/2021/060) proofs:
[PR #7](https://github.com/Safeheron/multi-party-ecdsa-cpp/pull/7)
added a no-small-factor proof, and
[PR #10](https://github.com/Safeheron/multi-party-ecdsa-cpp/pull/10) replaced the share-binding `pail_proof_` with the Paillier-Blum
Modulus proof ($N = pq$ with $p \equiv q \equiv 3 \pmod 4$) verified directly against $N$.