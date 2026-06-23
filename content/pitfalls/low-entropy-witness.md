---
title: "Witness Domain Has Insufficient Entropy"
class: cryptographic-primitives
hidden: true
order: 7
source: "fiat-shamir.md"
primitives: [zkp, randomness]
---

**What can go wrong.** A Fiat-Shamir proof of knowledge only authenticates the
prover if the witness is hard for anyone else to guess. If the witness space has
fewer than ~128 bits of entropy (a short PIN, a human-chosen passphrase, a
timestamp-derived value) an adversary can enumerate candidate witnesses offline
and then produce a genuine proof for the guessed value. Fiat-Shamir does not make
a guessable witness secret.

**Security implication.** The adversary guesses the witness value and then
produces a valid proof, so the proof no longer distinguishes the intended prover
from anyone who can search the witness space. In an MPC ceremony this lets a
corrupt participant masquerade as if it contributed a valid secret at keygen, or
authenticate to a role it does not hold. Because the proof is valid for the
guessed witness, no verifier-side check detects the problem.

**How to avoid.** Sample every witness from a space with at least 128 bits of
min-entropy. For human-chosen inputs, stretch entropy with a password-based KDF
(argon2id, scrypt) before the secret enters the protocol. For protocol-derived
witnesses, do not use small counters, session indices, or short bit-strings as the
value being proven.

**Example.** *TBD.* This is a structural entropy requirement rather than a
specific-CVE pitfall; it is typically caught in audit rather than in a single patch.