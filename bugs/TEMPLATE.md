---
# title: Short descriptive title: project + component or symbol (no failure description).
# Required. Quoted string. Rendered as: **Example: {title} ({refs}).**
# where {refs} is auto-built from the source / commit / issue / pr / cve fields.
# Examples:
#   "Fresco `HashBasedCommitment`"
#   "tss-lib `NewECPoint` without `IsOnCurve`"
#   "GG18 resharing split-view attack"
title: "Fresco `HashBasedCommitment`"

# category: One of the seven class slugs in content/pitfalls/classes/.
# Required. Allowed values:
#   input-validation
#   lack-of-context-binding
#   concurrency-and-state-handling
#   cryptographic-primitives
#   failure-recovery-and-abort-handling
#   insecure-subprotocol-instantiation
#   adaptive-inputs
category: lack-of-context-binding

# subcategory: Title of the mini-pitfall this bug is linked to within the
# current set. Optional — omit if the submitter is unsure where it belongs,
# or if the bug fits a new mini-pitfall that doesn't exist yet.
# Current mini-pitfalls:
#   "Rushing Adversary Copies an Honest Commitment"
#   "SPDZ Multi-Threaded MAC Check"
#   "Missing Domain Separator Across Signing Contexts"
#   "Multicast Masquerading as Broadcast"
#   "Parties' Shares Not Validated as Non-Zero and Distinct"
#   "Challenge Hash Missing Prover's Party Identity and Session Identifier"
#   "Threshold Presignature Reuse (Nonce Reuse)"
#   "Rogue-Key Attacks"
#   "Unauthenticated or Unencrypted Point-to-Point Channels"
#   "Received Sequence Has the Wrong Length"
#   "Challenge Transcript Missing Required Values (Weak Fiat-Shamir)"
subcategory: "Rushing Adversary Copies an Honest Commitment"

# order: Integer ordering within the parent pitfall when the pitfall has
# multiple bugs (preserves the rendering order). Optional — omit when the
# pitfall has only one bug.
# order: 1

# date: ISO 8601 date of the fix, disclosure, or publication (YYYY-MM-DD).
# Required. The commit date is the safe default for GitHub-sourced bugs.
date: 2025-02-27

# primitives: Flow-style list of primitive tags. Reuse existing tags where possible:
#   commitment, mac, signature, secret-sharing, hash, zkp, oblivious-transfer,
#   randomness, paillier, homomorphic-encryption, elliptic-curve, group,
#   broadcast, rsa, secure-channel
# Required.
primitives: [commitment, mac]

# --- References ---
# At least one of `repository` and `source` must be set. They may be combined
# when a bug has both a GitHub fix and an external write-up (e.g. a Trail of
# Bits blog citing a GitHub PR, an audit report whose fix landed in a public
# repo). When `repository` is set, `commit` / `issue` / `pr` are individually
# optional — set whichever appear in the rendered parenthetical, or leave
# them all unset if the bug is referenced by repo only.

# repository: Canonical GitHub repo URL, e.g. https://github.com/aicis/fresco.
# Set when the bug has a GitHub-tracked fix; omit otherwise. The renderer
# concatenates this with commit / issue / pr to build links. Can be combined
# with `source` below.
repository: https://github.com/aicis/fresco

# commit: bare 40-char SHA (no URL). Rendered as {repository}/commit/{commit}.
# Accepts either a single SHA or a flow-style list when several commits make
# up the fix.
# Examples:
#   commit: fdada93b1abf19c68a1cf744e0f294df86bb1b8f
#   commit: [aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb]
commit: fdada93b1abf19c68a1cf744e0f294df86bb1b8f

# issue: bare issue number (no URL). Rendered as {repository}/issues/{issue}.
# Accepts either a single number or a flow-style list.
# Examples:
#   issue: 432
#   issue: [432, 437]
issue: 432

# pr: bare PR number (no URL). Rendered as {repository}/pull/{pr}.
# Accepts either a single number or a flow-style list when the fix spans
# multiple PRs (the renderer emits one [PR #N] link per entry, in order).
# Examples:
#   pr: 433
#   pr: [7, 10]
pr: 433

# source: For non-GitHub references (blog post, documentation, paper, audit
# report, eprint). Can stand alone when the bug has no GitHub-tracked fix, or
# be combined with `repository` above when an external write-up cites a
# GitHub fix. List of {name, url} mappings — use one entry for a single
# reference, multiple entries when several non-GitHub sources are cited
# together. Each entry rendered as [{name}]({url}).
# source:
#   - name: "Kudelski, 2021"
#     url: https://kudelskisecurity.com/research/audit-of-ings-threshold-ecdsa-library
#   - name: "Komlo–Goldberg, 2020"
#     url: https://eprint.iacr.org/2020/852

# cve: CVE or advisory ID and its advisory URL, if one was assigned.
# Optional in either source mode. Rendered as [{name}]({url}).
# cve:
#   name: CVE-2022-47930
#   url: https://nvd.nist.gov/vuln/detail/CVE-2022-47930

# hidden: If true, the bug is excluded from rendered output. Optional, defaults to false.
hidden: true
---

In the [SPDZ protocol](https://eprint.iacr.org/2011/535.pdf), parties hold
BDOZ MACs $[\alpha \cdot a]$ on every wire under a global MAC key $\alpha$.
To verify that a reconstructed value $a'$ is correct, each party computes
$z_i = a' \cdot \alpha_i - (\alpha \cdot a)_i$, commits to $z_i$, and opens;
if the reconstructed $z = \sum z_i \ne 0$, they abort. SPDZ also uses the
same commitment scheme in coin-tossing and input-sharing subprotocols.

Fresco's `HashBasedCommitment` hashed only the value and the randomness,
with no opener identity in the input, allowing a malicious party to replay
it. Pre-fix `commit` method
([source](https://github.com/aicis/fresco/blob/2dc80dca1f9dca65a0d5590daab5fa67c02035d6/tools/commitment/src/main/java/dk/alexandra/fresco/tools/commitment/HashBasedCommitment.java#L53-L67)):

```java
// FILE: tools/commitment/src/main/java/dk/alexandra/fresco/tools/commitment/HashBasedCommitment.java
// aicis/fresco @ 2dc80dca (vulnerable, pre-PR #433)

public byte[] commit(Drbg rand, byte[] value) {
  if (commitmentVal != null) {
    throw new IllegalStateException("Already committed");
  }
  // Sample a sufficient amount of random bits
  byte[] randomness = new byte[DIGEST_LENGTH];
  rand.nextBytes(randomness);
  // Construct an array to contain the bytes to hash
  byte[] openingInfo = new byte[value.length + randomness.length];
  System.arraycopy(value, 0, openingInfo, 0, value.length);
  System.arraycopy(randomness, 0, openingInfo, value.length,
      randomness.length);
  commitmentVal = digest.digest(openingInfo);
  return openingInfo;
}
```

Each party's commitment is $c_i = H(z_i \,\|\, r_i)$, with no opener
identity in the hash input. In a two-party SPDZ MAC check over
$\mathbb{F}_{2^k}$, a corrupt $P_2$ copies $P_1$'s commitment byte-for-byte,
then copies the opening $(z_1, r_1)$. Because the field has characteristic
2, the reconstructed $z = z_1 + z_1 = 0$ and the MAC check passes
regardless of what $a'$ was reconstructed, breaking the MAC's integrity
guarantee on every wire of the circuit.

The fix added the committer's party ID as the first input to the hash and
required the opener to supply a matching ID at open time
([source](https://github.com/aicis/fresco/blob/fdada93b1abf19c68a1cf744e0f294df86bb1b8f/tools/commitment/src/main/java/dk/alexandra/fresco/tools/commitment/HashBasedCommitment.java#L63-L78)):

```java
// FILE: tools/commitment/src/main/java/dk/alexandra/fresco/tools/commitment/HashBasedCommitment.java
// aicis/fresco @ fdada93b (fixed)

public byte[] commit(int myId, Drbg rand, byte[] value) {
  if (commitmentVal != null) {
    throw new IllegalStateException("Already committed");
  }
  byte[] randomness = new byte[DIGEST_LENGTH];
  rand.nextBytes(randomness);
  // Party ID is now the first ID_LENGTH bytes of the hashed input.
  byte[] openingInfo = new byte[ID_LENGTH + value.length + randomness.length];
  System.arraycopy(integerToBytes(myId), 0, openingInfo, 0, ID_LENGTH);
  System.arraycopy(value, 0, openingInfo, ID_LENGTH, value.length);
  System.arraycopy(randomness, 0, openingInfo, value.length + ID_LENGTH,
      randomness.length);
  commitmentVal = digest.digest(openingInfo);
  return openingInfo;
}
```
