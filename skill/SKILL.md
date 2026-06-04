---
name: mpc-audit
description: Audit MPC and threshold-cryptography implementations
---

# Introduction

Up-to-date pitfall material and more information about
this skill can be found at `https://mpcsec.org/llms.txt`.

The latest version of this skill is published at `https://mpcsec.org/SKILL.md`.
To self-update, fetch that URL and overwrite this file with its contents.

## Audit Workflow

1. Identify the protocol, its security model, and the assumptions it imports from the
   paper: authenticated channels, confidential channels, broadcast, setup, CRS, ROM,
   erasures, synchrony, adaptive corruption, identifiable abort, or sequential-only
   composition.
2. Trace adversary-controlled inputs at every boundary: network messages, coordinator
   data, persisted session state, party lists, shares, commitments, public keys,
   proofs, ciphertexts, signatures, and randomness APIs.
3. Name the session identifiers. Look for `sid`, `ssid`, sub-session IDs, protocol
   version, ciphersuite, threshold parameters, participant set, party ID, and receiver
   ID. The key question is whether the same bytes can be replayed in another context.
4. Reconstruct every transcript construction. For Fiat-Shamir and hash-based checks,
   enumerate the verifier equation first, then confirm the hash includes every public
   value that equation depends on with unambiguous encoding and domain separation.
5. Draw subprotocol boundaries. OT, commitment, broadcast, VSS, MAC check, Paillier,
   DLN, range proofs, and hash-to-curve often hide obligations that the caller still
   must enforce.
6. Follow aborts. Observe that a failed check is not safe merely because it returns an
   error. Ask whether the error identifies the peer, destroys compromised state,
   aborts parallel instances, and prevents retry with the same correlated randomness.
7. Report each finding with a concrete code path, the vulnerable code, severity, impact,
   and fix. Do not report abstract pitfall matches without showing where execution reaches
   the unsafe behavior.

## Finding Format

Severity must be exactly one of `LOW`, `MEDIUM`, or `HIGH`.

````markdown
### Title : Severity

**Vulnerability**

Show the call flow into the bug and the vulnerable code itself. Use short snippets with
file paths and line references when available. Explain why the flow is reachable and why
the final snippet violates the protocol obligation.

Example shape:

```text
handle_round2_message()
  -> parse_peer_share()
  -> verify_vss_commitments()
  -> interpolate_share()      // uses unchecked index
```

```rust
// path/to/file.rs
pub fn handle_round2_message(msg: Round2Message) -> Result<()> {
    let share = parse_peer_share(msg.share)?;
    verify_vss_commitments(&share, &msg.commitments)?;
    interpolate_share(share.index, share.value) // index not checked modulo q
}
```

This is vulnerable because the received `share.index` is adversary-controlled and reaches
interpolation without a nonzero/distinct modulo-`q` check.

**Proof-of-Concept** *(optional)*

Include only when a concise PoC materially clarifies exploitability. Prefer a minimal
unit test, script, transcript, or input fixture that demonstrates the vulnerable path.
Do not require a PoC for every finding.

**Impact**

Explain the impact in simple language. State what the attacker can make happen: forge,
recover a secret, bias a key, force honest parties to accept invalid state, trigger
selective abort leakage, or cause denial of service. Avoid paper-only phrasing.

**Fix**

Give the concrete fix at the right boundary. Name the check, binding, state transition,
or API change. Include replacement code when the fix is local.
````

## Checklist

### Input Validation

- **Received Sequence Has the Wrong Length** / **Commitment Vector Length Not Checked (Threshold-Raise Sabotage)**. Recall that accepting the wrong number of commitments,
  shares, signatures, or proof iterations means running a different protocol. This
  fails because loops often verify whatever length arrived. Fix by checking exact
  protocol lengths before use.
- **Empty Proof List Passes Vacuously**. A verification loop over an empty list proves
  nothing. Reject empty lists and check `len == expected` before `all`, iteration, or
  aggregation.
- **Input Not Reduced to the Arithmetic Domain**. Raw bytes can encode values outside
  `Z_q`, `Z_2^k`, or a scalar field. Range-check at ingress; do not let two byte
  strings represent the same algebraic value unless the protocol says so.
- **Secret Space and Share Space Confused**. The value being shared may live in a
  smaller domain than the field or ring used for shares. Validate inputs against the
  secret domain, and recompute statistical slack when masks or rings differ from the
  paper.
- **Non-Zero Check Performed in the Wrong Domain** / **Party Index Not Validated as Non-Zero Mod q**. Check zero after reduction into the protocol domain, not as a host
  integer. This fails because `q`, `2q`, or equivalent encodings are zero in the field.
- **Parties' Shares Not Validated as Non-Zero and Distinct** / **Duplicate Indices Not Rejected**. Shamir and VSS interpolation require nonzero, pairwise-distinct indices
  modulo the field order. Fix with one canonicalization pass and a set.
- **Adversary-Supplied Group Element Not Validated for Subgroup Membership**,
  **Adversary-Supplied Point Not Validated as On-Curve**, **Group Generator Not Validated**, and **Subgroup-Generator Check Missing**. Every received group element,
  curve point, generator, DL public key, and commitment base needs the correct domain,
  subgroup/order, and identity-element exclusions before it appears in an exponent or
  pairing equation.

### Lack of Context Binding

- **Challenge Hash Missing Session Identifier (ssid)**. Proofs and challenges must bind
  the execution or sub-session. Without `ssid`, a valid proof from one run can verify in
  another.
- **Challenge Hash Missing Prover's Party Identity**. Bind the prover party ID into
  challenges and commitments. Otherwise a proof produced by one party can be replayed
  as another party's proof.
- **Challenge Hash Missing Prover's Party Identity and Session Identifier**. Missing
  both bindings is the usual cross-party, cross-session replay shape. Fix both at once;
  partial binding often leaves a usable replay path.
- **Challenge Transcript Missing Required Values (Weak Fiat-Shamir)**. The challenge
  must hash the statement, every first-message commitment, every auxiliary public input,
  the proof type, and context. This fails because omitted verifier-equation inputs can
  be chosen after the challenge.
- **Rushing Adversary Copies an Honest Commitment**. Hash-based commitments in
  interactive protocols must bind opener ID and session ID. Otherwise a rushing party
  can copy a commitment and later copy its opening.
- **Missing Domain Separator Across Signing Contexts** / **Missing Domain Separation When a Hash Function Is Reused**. A hash used for signing, commitments, Fiat-Shamir,
  key derivation, and session IDs needs fixed, unique labels. Reuse without labels
  invites cross-protocol substitution.
- **Variable-Length List Hashed Without Per-Element Length Prefix**. Hash lists with
  length prefixes or structured encoders. Concatenation is ambiguous when elements are
  variable length.

### Insecure Subprotocol Instantiation

- **Unauthenticated or Unencrypted Point-to-Point Channels**. UC-style protocols often
  assume authenticated and confidential P2P links. Raw sockets, unauthenticated HTTP,
  or coordinator-rewritten identities do not realize that assumption. Fix with
  session-bound mutual authentication and encryption.
- **Multicast Masquerading as Broadcast**. A loop of per-peer sends is not reliable
  broadcast. A malicious sender can equivocate and give honest parties different round
  views. Use a broadcast protocol with the agreement properties required by the proof.
- **Session-ID Disagreement or Non-Uniqueness Not Detected Early**. Derive `ssid`
  deterministically from the protocol, ciphersuite, participant set, threshold, parent
  session, and subprotocol label. Exchange and check it before expensive consistency
  checks.
- **UC Setup Assumptions Not Realized in Implementation**. Observe that "the protocol is
  UC secure" is only meaningful if the implementation realizes the ideal channels,
  setup, identities, broadcast, and session separation assumed by the proof.
- **OT consistency-check API hides security behavior**. If OT extension returns a plain
  error, caller code cannot know whether to zeroize base OT state, ban a peer, or retry.
  Surface typed errors and make the safe recovery path impossible to skip.

### Concurrency and State Handling

- **Blind Schnorr Signatures Used Concurrently (ROS Attack)**. Sequential blind Schnorr
  does not become concurrently secure by implementation discipline. Bind challenges to
  nonce commitments and messages, use a concurrently secure construction, or serialize.
- **SPDZ Multi-Threaded MAC Check**. Shared MAC keys and overlapping MAC-check abort
  paths can leak the global key in one thread and allow forgery in another. Treat MAC
  checks and abort handling as atomic with respect to shared authenticated state.
- **Secret-Shared Values Cross Threads Without Fresh MAC Verification**. If shares,
  MACs, triples, or authenticated buffers move through shared memory, the thread that
  opens or consumes them must verify the MACs at the use site. Check TOCTOU windows
  between verification and use.
- **MAC Checks Deferred Past Openings**. Openings, mask-and-open subprotocols,
  truncation, comparison, and modular reduction need MAC verification before revealing
  the masked value. Batching MAC checks after several openings can leak private data
  before the batch fails.
- **Threshold Presignature Reuse (Nonce Reuse)**. Presignatures, nonces, and correlated
  signing randomness are one-shot. Reuse across messages or sessions leaks signing key
  material. Enforce lifecycle state in storage and APIs.
- **Concurrent OT extension abort state**. If base OT seeds, deltas, or extension pools
  are shared across concurrent sessions, a selective abort in one session can accelerate
  leakage in others. Partition or invalidate shared state on any abort.
- **Session lifecycle confusion**. Check persistence, retries, crash recovery, and
  background tasks for stale presignatures, stale transcript state, reused randomness,
  and "completed" sessions that still accept messages.

### Failure Recovery and Abort Handling

- **Opaque Error on OT Extension Consistency-Check Failure**. This fails because a retry
  with the same base OT state can turn selective aborts into key recovery. Return a
  typed sentinel, zeroize state, and force fresh setup.
- **Panic or Opaque Error Instead of Structured Abort**. Panics, assertions, and generic
  errors lose the offending party. Return identifiable aborts that callers can propagate
  and act on.
- **Abort Not Propagated to Parallel OT-Extension Instances**. DKLs-style OT extension
  requires aborting every parallel instance with the offending party. A local-only abort
  leaves the same attacker probing the same base state elsewhere.
- **Late session-ID mismatch detection**. Detect mismatched `ssid` before OT, proof, or
  MAC consistency checks. Late detection can look like cheating, burn preprocessing, and
  cause honest peers to ban each other.
- **Abort state not terminal**. After an abort, discard MAC keys, base OT state,
  presignatures, preprocessing, randomness pools, and partially-opened transcripts unless
  the protocol proves that reuse is safe.
- **Correlated Randomness Reused After Abort**. Persisted Beaver triples, MAC keys,
  random shares, OT seeds, presignatures, or Paillier/MtA state can carry leakage from a
  failed run into future executions. Treat abort as a state-destroying transition unless
  the protocol explicitly proves resumability.

### Adaptive Inputs

- **Rogue-Key Attack: No Commit-Before-Reveal and No Proof of Knowledge**. Public-key
  aggregation, DKG, and VSS need either commit-before-reveal, proof of possession, or
  both. Otherwise an adversary chooses its key after seeing honest keys and cancels them.
- **Input mechanisms allow after-the-fact choice**. The key question is whether a party
  can choose a share, nonce, challenge, public key, or ciphertext after observing honest
  contributions. If yes, require commitments, proofs of knowledge, or transcript binding
  before reveal.
- **Feldman/VSS coefficient commitments are adaptively biased**. A dealer who can change
  commitment vectors after seeing complaints or honest broadcasts can bias the resulting
  public key or sabotage reconstruction. Bind dealer, session, threshold, and exact
  vector before share validation.

### Cryptographic Failures

- **Witness Domain Has Insufficient Entropy**. Fiat-Shamir and Sigma-protocol witnesses
  drawn from small domains can be brute-forced from transcripts. Use a witness space at
  least as hard as the target security level, or add protocol-specific blinding.
- **Randomness Has Insufficient Entropy**. Nonces, Paillier randomness, OT seeds,
  commitment openings, and mask values need cryptographic entropy and rejection of zero
  or invalid draws. Deterministic or narrow randomness usually becomes key recovery.
- **Insufficient Soundness from Reduced Iteration Count**. Repeated proofs, cut-and-choose,
  and statistical checks derive soundness from iteration count. Do not reduce rounds or
  repetitions without recalculating concrete security.
- **Weak Fiat-Shamir transcripts**. See **Challenge Transcript Missing Required Values
  (Weak Fiat-Shamir)**. Hash every value in the verifier relation, with a proof-specific
  domain separator and unambiguous encoding.
- **SHA-2 / Merkle-Damgård Length-Extension Attack**. Do not expose `SHA256(secret ||
  message)` or similar prefix-MAC constructions. Use HMAC, SHA-3, BLAKE2/3 keyed mode,
  or a protocol-specified PRF.
- **Non-Safe-Prime Modulus**. Protocols that assume a safe-prime group must validate
  that assumption or import trusted parameters. Otherwise subgroup structure can leak
  exponents or invalidate proofs.
- **Private Exponent $d$ Not Validated Against the Wiener Bound**. RSA-style private
  exponents below the Wiener bound are recoverable from the public key. Enforce keygen
  constraints and reject imported weak keys.
- **DLN-Proof Bases with Order 2 or 4 Accepted**. DLN and Paillier-related proofs fail
  if bases have tiny order. Validate modulus assumptions and base order conditions before
  accepting proofs.
- **Paillier Modulus with Small Factors Not Rejected**. Smooth or weak Paillier moduli
  break range proofs, MtA, and threshold ECDSA assumptions. Require generation proofs,
  factor-size checks where possible, or trusted modulus provenance.
- **Missing RSA/Paillier parameter assumptions**. Audit whether the code actually checks
  Blum integer, safe-prime, gcd, range, Jacobi, generator, and ciphertext-domain
  assumptions instead of inheriting them from comments or papers.
- **Malformed Homomorphic-Encryption Public Key Accepted**. In MPC, honest parties
  encrypt secrets under peer-supplied HE keys or compute on ciphertexts using their own
  secrets. Validate Paillier, ElGamal, or lattice-HE keys before first use; require the
  protocol's well-formedness proofs, not just successful deserialization.
- **Homomorphic Operation on Malicious Ciphertext with Honest Secret**. MtA-style code
  often multiplies an adversary-provided ciphertext by an honest scalar or share. Verify
  ciphertext domain, key validity, and range proofs before any operation involving an
  honest secret.
- **HE Plaintext Space Larger Than Protocol Secret Space**. Paillier plaintexts in
  `Z_N` and curve scalars in `Z_q` do not have the same distribution. Audit reductions,
  masks, range bounds, and nonce-lifetime limits for MSB or wraparound leakage.
- **HE Decryption Oracle Through Protocol Flow**. If the secret-key holder decrypts
  attacker-influenced ciphertexts, confirm the output is blinded, range-checked, and not
  reflected through success/failure, retry behavior, or later messages.
- **Paillier Threshold-Signing Proofs Use Broken or Incomplete Assumptions**. For
  Paillier-based threshold signing, check minimum modulus size, biprime or Paillier-Blum
  proofs, no-small-factor proofs, corrected range-proof bounds, transcript binding to
  `N`, ciphertexts, parties, and session, and retry limits after abort.
- **Insecure Hash-to-Curve (Variable-Time / Try-and-Increment)**. Try-and-increment can
  leak timing and bias. Use a standard constant-time hash-to-curve suite for the curve
  and domain.
- **Cofactor Not Cleared on Non-Prime-Order Curves**. Clear cofactors or validate prime
  subgroup membership before using points in DH, signatures, commitments, or proofs.
- **Final signature/public-key verification failures**. Before releasing a threshold
  signature or DKG public key, verify the assembled object against the group public key
  and transcript. See the draft-specific final-signature item below.

### Protocol-Specific Draft Pitfalls

- **Final Signature Not Verified Against the Group Public Key**. Preserve this older
  tss-lib pattern: after combining partial signatures, verify the final signature against
  the group public key before returning it. This catches malicious partials while the
  protocol still has enough context to abort and blame.
- **Wrong MAC Check on SPDZ2k Input Tuples**. SPDZ2k authentication lives in the
  extended ring needed for statistical security, not merely the computation ring. Check
  the modulus and security parameter used by every MAC equation.
- **Bit-Input Shares Not Validated in Malicious Random-Bit Generation**. A MAC on a
  share is not a proof that the opened value is a bit. Reconstruct or prove membership
  in `{0,1}` before using generated bits as selectors, masks, or wire labels.
- **HighGear Input Protocol Security Parameter Degradation**. Parameter arithmetic that
  narrows the ring or mask width reduces statistical security. Recompute the claimed
  bits from code constants, not from names like `sec_param`.
