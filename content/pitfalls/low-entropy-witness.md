---
title: "Witness Domain Has Insufficient Entropy"
class: others
hidden: true
source: "fiat-shamir.md"
primitives: [zkp, randomness]
---

### Witness Domain Has Insufficient Entropy

<div class="pitfall-flags"><span class="flag flag-tbd">TBD example</span></div>

**What can go wrong.** A Fiat-Shamir proof of knowledge is only meaningful if the witness
the prover claims to know is drawn from a domain the adversary cannot brute-force
offline. If the witness space has fewer than ~128 bits of entropy — a short PIN, a
human-chosen passphrase, a timestamp-derived value — an adversary can enumerate all
candidate witnesses, compute the FS proof for each, and submit one that matches the
transcript. The soundness of FS assumes the witness is computationally inaccessible; it
does not make a guessable witness unguessable.

**Security implication.** The adversary produces a valid proof without ever having had
access to the honest party's witness. In an MPC ceremony this lets a corrupt participant
masquerade as if it contributed a valid secret at keygen, or authenticate to a role it
does not hold. Because the forged proof is a genuine FS artifact, no verifier-side check
detects it.

**How to avoid.** Sample every witness from a space with at least 128 bits of
min-entropy. For human-chosen inputs, stretch entropy with a password-based KDF
(argon2id, scrypt) before the secret enters the protocol. For protocol-derived
witnesses, do not use small counters, session indices, or short bit-strings as the
value being proven.

**Example.** *TBD.* This is a structural entropy requirement rather than a
specific-CVE pitfall; it is typically caught in audit rather than in a single patch.
