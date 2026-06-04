---
# title: Short descriptive pitfall title.
# Required. Quoted string. Rendered as the pitfall heading and shown as the
# bug's "Pitfall" link in the tracker, so keep it stable once bugs reference
# this pitfall.
# Good titles name the missing check or unsafe pattern, not one concrete project.
# Examples:
#   "Curve Points Not Validated"
#   "Missing Domain Separator Across Signing Contexts"
#   "Received Sequence Has the Wrong Length"
title: "Missing Domain Separator Across Signing Contexts"

# class: One of the categories in content/pitfalls/classes/.
# Required. This controls which category section renders the pitfall.
# Current categories values:
#   input-validation
#   lack-of-context-binding
#   concurrency-and-state-handling
#   cryptographic-primitives
#   failure-recovery-and-abort-handling
#   insecure-subprotocol-instantiation
#   adaptive-inputs
class: lack-of-context-binding

# hidden: If true, the pitfall is excluded from rendered output.
# Optional, defaults to false. Use true for drafts or speculative entries.
hidden: true

# order: Integer ordering within the class section.
# Required for visible pitfalls. Pick the next available order within the class.
order: 1

# source: Optional provenance note for migration from old/older/*.md or another
# internal source document. This is not rendered as a citation by the current
# templates; it is mostly editorial bookkeeping.
# Examples:
#   source: "zk-proofs-not-bound.md"
#   source: "hash-functions.md"
source: "zk-proofs-not-bound.md"

# primitives: List of cryptographicprimitive tags. Existing tags include:
#   commitment, mac, signature, secret-sharing, hash, zkp, oblivious-transfer,
#   randomness, paillier, homomorphic-encryption, elliptic-curve, group,
#   broadcast, rsa, secure-channel
# Required. These help classify both pitfalls and bugs.
primitives: [zkp]

# bugs: Ids of every real-world bug associated with this pitfall, where each id
# is a file name (without .md) under content/bugs/. Drives the bug tracker:
# each listed bug appears there and inherits this pitfall's `class` as its
# category. Optional — omit when no bug is linked yet.
# Example: bugs: [tss-lib-schnorr-pok, coinbase-kryptology-gg20-dkg]
bugs: [tss-lib-schnorr-pok]

# display: The subset of `bugs` rendered as inline examples on the homepage,
# in this order. Every id here must also appear in `bugs`. Use it to feature
# the clearest cases while keeping the rest tracker-only. Omit to show none.
# Example: display: [tss-lib-schnorr-pok]
display: [tss-lib-schnorr-pok]
---

**What can go wrong.** Describe the unsafe implementation pattern in general terms.
Start from the protocol surface: what object is exchanged, computed, verified, or
stored? Then name the missing invariant. Keep the pitfall reusable across projects;
save project-specific details for `content/bugs/*.md`.

For example, in the Fiat-Shamir transformation, a verifier's challenge must bind to
every public value that the verification equation depends on: the statement, the
commitment(s), the party identity, the session identifier, and any auxiliary public
inputs. If one of those values is omitted from the transcript hash, a prover may be
able to replay a proof across contexts or choose the omitted value after seeing the
challenge.

**Security implication.** Explain the attacker outcome, not just the violated rule.
Be concrete about what the failure causes it can be forgery, key-share extraction,
threshold manipulation, denial of service, biased randomness, transcript replay,
selective abort, or loss of session isolation. If useful, include a short algebraic
sketch:

- What does the attacker choose?
- What does the honest implementation accept?
- Which secret, guarantee, or availability property is lost?

**How to avoid.** Give mitigation strategies that an auditor or developer can
apply. Prefer crisp requirements over broad advice.

For example,
- Bind transcript hashes to protocol name, version, role, party identity, session
  identifier, statement, commitments, and all public verification inputs.
- Make wire encodings injective with fixed-width tags or per-element length prefixes.
- Validate received algebraic objects before using them with secrets.
- Abort with enough structure to identify the failed peer and propagate cancellation
  to related sessions when the protocol requires it.

<!--
Real-world examples belong in separate files under content/bugs/.
Add each bug's id to this pitfall's `bugs` array (and to `display` to show it on
the homepage); the homepage and bug tracker link them automatically from there.
-->
