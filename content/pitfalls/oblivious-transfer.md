---
title: "Oblivious Transfer"
class: "Cryptographic Primitive"
order: 15
---

- Many oblivious transfer extension protocols rely on consistency checks to get active security. However, they suffer from selective abort attacks, where succeeding or failing a consistency check leaks a few bits of information on the underlying OT secret. As a result, reusing the base OT secrets for multiple OT extension protocols is dangerous.
    - [DKLs23](https://eprint.iacr.org/2023/765.pdf) states that an abort during OT extension requires the involved party to abort all instances of the protocol running in parallel that involve the offending party. This is extremely difficult to guarantee from an engineering standpoint.

### Example

The KOS OT extension in Coinbase kryptology returns a generic `error` on consistency-check failure, with no signal that base OT state must be invalidated ([source](https://github.com/coinbase/kryptology/blob/eef703320df46f97e86ead4eff178b095181b0ec/pkg/ot/extension/kos/kos.go#L269-L365)):

```go
// pkg/ot/extension/kos/kos.go — Coinbase kryptology
func (sender *Sender) Round2Transfer(
    uniqueSessionId [simplest.DigestSize]byte,
    input [L][OtWidth]curves.Scalar,
    round1Output *Round1Output,
) (*Round2Output, error)
```

A caller receiving this error has no way to distinguish a benign network failure from a malicious consistency-check violation. If the caller retries with the same base OTs, each attempt leaks bits of the base OT secret via selective abort.

- In Silence Laboratories' dkls23 implementation (used by MetaMask), the OT extension consistency check panicked on failure instead of returning a structured error identifying the offending party (TOB-SILA-12). Without identifiable abort, the application cannot determine which party cheated; if it blames everyone and destroys the key, that enables a key destruction attack; if it blames no one and allows retry, that enables key extraction.
- Trail of Bits observed this pattern systematically: "most OT extension libraries will report something along the lines of 'correlation check failed,' which does not tell a user what to do next."

### References

- Trail of Bits, [Don't overextend your Oblivious Transfer](https://blog.trailofbits.com/2023/09/20/dont-overextend-your-oblivious-transfer/), September 2023.
- Trail of Bits, [audit of Silence Laboratories](https://github.com/nicedayzhu/silence-laboratories-multiparty-sig/blob/main/docs/Trail_of_Bits_Silence_Laboratories_Multi-Party_Threshold_Signature_Scheme_Security_Assessment.pdf) (TOB-SILA-12), April 2024.
- [DKLs23](https://eprint.iacr.org/2023/765.pdf).

---

# DRAFT Oblivious Transfer

Oblivious Transfer (OT) is a two-party sub-protocol in which a sender holds two secrets $m_0, m_1$ and a receiver holds a choice bit $b$; the receiver learns $m_b$ and nothing about $m_{1-b}$, while the sender learns nothing about $b$. OT underlies virtually all practical MPC: it drives the offline phase of garbled circuits, provides the correlated randomness consumed by SPDZ-family protocols, and is the backbone of modern 2-party ECDSA protocols such as Lindell17 and DKLs23.

In practice, OT is instantiated via **OT extension** (IKNP03, KOS15): a small number of "base OTs" (using public-key cryptography) bootstrap an unlimited number of cheap OTs using only symmetric-key operations. This architecture creates two distinct implementation pitfalls:

1. **Selective abort leakage**: OT extension includes a consistency check that a malicious receiver can *selectively fail*, causing the sender to abort. Each abort leaks a small number of bits of the sender's base-OT secrets. If base-OT secrets are reused across multiple extension runs, a cheating receiver accumulates these bits across sessions until it has recovered the entire base-OT state — at which point it can decrypt all past and future OT messages. As Trail of Bits observed: *"most OT extension libraries will report something along the lines of 'correlation check failed,' which does not tell a user what to do next."*

2. **Non-identifiable abort**: When the consistency check fails, the implementation must identify *which party* cheated so that honest parties can ban it and continue. A panic or opaque error obscures the identity of the offending party, forcing honest parties to choose between banning everyone (a key-destruction attack) or retrying without exclusion (a key-extraction attack). [DKLs23](https://eprint.iacr.org/2023/765.pdf) makes this obligation explicit: an abort during OT extension requires the involved party to abort *all* protocol instances running in parallel that involve the offending party — a requirement that is extremely difficult to guarantee from an engineering standpoint when the abort signal carries no party identity.

### Example 1: Opaque Error on Consistency-Check Failure — Coinbase kryptology (v1.6.0)

The KOS OT extension in `coinbase/kryptology` implements Protocol 9 of DKLs18. When the sender's consistency check fails, `Round2Transfer` returns a plain `error` value
([source](https://github.com/coinbase/kryptology/blob/eef703320df46f97e86ead4eff178b095181b0ec/pkg/ot/extension/kos/kos.go#L269-L365)):

```go
// FILE: pkg/ot/extension/kos/kos.go — coinbase/kryptology (pre-v1.6.1)

func (sender *Sender) Round2Transfer(
    uniqueSessionId [simplest.DigestSize]byte,
    input [L][OtWidth]curves.Scalar,
    round1Output *Round1Output,
) (*Round2Output, error) {
    ...
    if subtle.ConstantTimeCompare(zPrime[:], rhs[:]) != 1 {
        // Returns an error but the caller has no structured way to know
        // the base OT state is now compromised and must be discarded.
        return nil, fmt.Errorf("cOT receiver's consistency check failed; " +
            "this may be an attempted attack; do NOT re-run the protocol")
    }
    ...
}
```

The error string warns against re-running but there is no machine-readable signal. Any caller that catches the error via a generic `if err != nil` block has no way to distinguish a network timeout from a malicious consistency-check violation, and no automatic enforcement that the base OT seed is destroyed.

**Attack.** A cheating receiver manipulates its inputs to the consistency check so that it fails selectively — it causes the check to fail only when a specific target bit of the sender's base-OT choice vector $\Delta$ matches a particular value. If the protocol aborts, the receiver learns that bit; if it does not, the receiver learns the complement. By repeating this across multiple OT extension calls (each time targeting the next unknown bit), the receiver recovers $\Delta$ entirely. With $\Delta$ known, the receiver can decrypt all OT messages the sender has ever sent or will send, breaking the confidentiality guarantee for every wire in every garbled circuit or MPC computation that consumed these OTs.

**Remediation.** Version 1.6.1 of kryptology fixed a transcription error in the DKLs18 KOS cOT sub-protocol that made the consistency check itself incorrect, and the new DKLs18 implementation (v1.6.0) separated OT, OT extension, and Schnorr ZKP into dedicated packages with explicit session-scoped state. The base-OT seed is now tied to a single extension session; a failed check invalidates the seed object, preventing any silent reuse ([source](https://github.com/coinbase/kryptology/blob/eef703320df46f97e86ead4eff178b095181b0ec/pkg/ot/extension/kos/kos.go)):

```go
// FILE: pkg/ot/extension/kos/kos.go — coinbase/kryptology v1.6.1 (fixed)

// On consistency check failure the seed is explicitly zeroized.
if subtle.ConstantTimeCompare(zPrime[:], rhs[:]) != 1 {
    sender.seed.Zeroize()   // base OT state destroyed; no reuse possible
    return nil, ErrConsistencyCheckFailed  // typed sentinel error
}
```

Callers can now `errors.Is(err, kos.ErrConsistencyCheckFailed)` and know they must initiate a fresh base-OT setup before any further OT extension.

### Example 2: Missing Abort on Signature Failure in Lindell17 — CVE-2023-33242

Lindell17 is a two-party ECDSA protocol that uses an OT-derived multiplicative-to-additive (MtA) conversion during signing. The protocol specification explicitly requires that both parties **abort** if the reconstructed signature fails to verify under the group public key. This abort is a load-bearing security requirement: without it, a malicious client can use signature failure as a one-bit oracle.

In `ZenGo-X/gotham-city` and `ZenGo-X/multi-party-ecdsa` before v1.0.0, and in the Coinbase WaaS SDK React Native before v1.0.0, the server continued processing after a failed signature rather than aborting ([source](https://github.com/ZenGo-X/gotham-city/blob/07d1ca18d5b80346b8621c4980fbe86f88ca4544/gotham-engine/src/lib.rs)):

```rust
// FILE: gotham-engine/src/lib.rs — ZenGo-X/gotham-city (vulnerable, < v1.0.0)

// Server receives partial_sig from client and reconstructs (r, s).
// Per Lindell17 §3, if verify(pk, msg, r, s) fails the server MUST abort.
// The vulnerable code returned the invalid signature to the client instead.
let signature = party2.phase5(partial_sig)?;
// ← No call to verify(); server returns signature unconditionally
Ok(signature)
```

**Attack (bit-by-bit key extraction, ~256 signatures).** Fireblocks' Cryptography Research Team discovered this attack in May 2023 (publicly disclosed August 9, 2023 at Black Hat USA). The procedure:

1. The malicious client sets its nonce share $k_1 = 2$ and constructs a Paillier ciphertext $C$ such that the final signature verifies *if and only if* $\mathsf{lsb}(x_2) = 0$, where $x_2$ is the server's key share.
2. The server runs the MtA protocol using the malformed $C$. If $\mathsf{lsb}(x_2) = 0$ the signature verifies and the server returns it; otherwise, the signature is invalid. Without an abort, the server silently returns the invalid value, revealing through success/failure whether $\mathsf{lsb}(x_2) = 0$.
3. In iteration $i$, the client sets $k_1 = 2^i$ and adjusts the ciphertext to probe the $i$-th bit of $x_2$, correcting for previously recovered bits.
4. After approximately 200–256 iterations, the client has recovered all bits of $x_2$ and can reconstruct the full private key.

**Remediation.** `ZenGo-X/gotham-city` v1.0.0 (tagged July 31, 2023, commit [`07d1ca1`](https://github.com/ZenGo-X/gotham-city/commit/07d1ca18d5b80346b8621c4980fbe86f88ca4544)) added the mandatory signature verification and abort ([source](https://github.com/ZenGo-X/gotham-city/blob/07d1ca18d5b80346b8621c4980fbe86f88ca4544/gotham-engine/src/lib.rs)):

```rust
// FILE: gotham-engine/src/lib.rs — ZenGo-X/gotham-city (fixed, v1.0.0)

let signature = party2.phase5(partial_sig)?;

// Abort if the reconstructed signature does not verify — required by Lindell17 §3
if !verify(&signature, &public_key, &message_hash) {
    return Err(SigningError::InvalidSignature);
}
Ok(signature)
```

Coinbase patched the WaaS SDK React Native before public disclosure. The PoC exploit is available at [fireblocks-labs/zengo-lindell17-exploit-poc](https://github.com/fireblocks-labs/zengo-lindell17-exploit-poc).

### Example 3: Panic Instead of Identifiable Abort — Silence Laboratories dkls23 (TOB-SILA-12)

The DKLs23 protocol is a 2-of-2 threshold ECDSA scheme that uses OT extension for its multiplicative-to-additive conversion. DKLs23 is explicit that when an OT consistency check fails, the implementation must identify the *specific offending party* and ban it — and must simultaneously abort all other protocol instances running in parallel with that party, since the same base-OT secrets may have been probed across all of them.

In the [Silence Laboratories dkls23](https://github.com/silence-laboratories/dkls23) implementation (used by MetaMask's Silent Shard Snap), the OT extension consistency check triggered a Rust `panic!` on failure rather than returning a structured error ([source](https://github.com/silence-laboratories/dkls23/blob/main/src/proto/signing.rs)):

```rust
// FILE: src/proto/signing.rs — silence-laboratories/dkls23 (vulnerable, pre-audit)

// OT consistency check failure: panics instead of returning an identifiable error.
// The caller cannot determine which party cheated, preventing proper banning.
assert!(ot_check_passed, "OT consistency check failed");
// ↑ panic unwinds the stack; no party ID is propagated to the caller
```

**Attack.** A panic unwinds the Rust stack without propagating *which* party caused the failure. The application layer is left with two bad choices:

- **Key destruction**: Treat the panic as evidence that some party cheated and destroy the key share. An adversary who can trigger the panic at will gains the ability to destroy honest parties' keys without needing to know the key material — a *griefing* attack.
- **Retry without exclusion**: Treat the panic as a transient error and retry without banning the offending party. The offending party can repeat the selective-abort probe across multiple retries, accumulating bits of the base-OT state in the same manner as Example 1.

Additionally, because the abort does not propagate a party identity, any parallel protocol instances involving the same party cannot be terminated — exactly the requirement that DKLs23 places on the implementation.

**Remediation.** Trail of Bits identified this as TOB-SILA-12 in their April 2024 audit. Silence Laboratories patched the implementation to replace the `panic!` with a structured `AbortProtocolAndBanReceiver` error that carries the offending party's identifier ([source](https://github.com/silence-laboratories/dkls23/blob/main/src/proto/signing.rs)):

```rust
// FILE: src/proto/signing.rs — silence-laboratories/dkls23 (fixed)

if !ot_check_passed {
    // Return a typed error containing the party ID so the caller can:
    // 1. Ban the specific party
    // 2. Abort all parallel sessions with that party
    return Err(ProtocolError::AbortProtocolAndBanReceiver {
        party_id: offending_party,
    });
}
```

### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| Sep 20, 2023 | — | [Trail of Bits blog](https://blog.trailofbits.com/2023/09/20/dont-overextend-your-oblivious-transfer/) | "Don't overextend your Oblivious Transfer": publicly documents selective-abort leakage in OT extension and the danger of reusing base-OT state |
| ~2022 | [coinbase/kryptology](https://github.com/coinbase/kryptology) | v1.6.0 | Fix for "Fireblocks bit probe attack" on DKLs18-based OT; refactors OT, OT extension, and Schnorr ZKP into dedicated scoped packages |
| ~2022 | [coinbase/kryptology](https://github.com/coinbase/kryptology) | v1.6.1 | Fix transcription error in DKLs18 KOS cOT extension subprotocol; incorrect consistency check corrected |
| Sep 2022 | [coinbase/kryptology](https://github.com/coinbase/kryptology) | Repository archived | Kryptology archived as read-only; no further security patches |
| May 2023 | — | — | Fireblocks discovers Lindell17 abort vulnerability (CVE-2023-33242); 90-day responsible disclosure begins |
| Jul 31, 2023 | [ZenGo-X/gotham-city](https://github.com/ZenGo-X/gotham-city) | [v1.0.0 / commit `07d1ca1`](https://github.com/ZenGo-X/gotham-city/commit/07d1ca18d5b80346b8621c4980fbe86f88ca4544) | Fix CVE-2023-33242: add mandatory signature verification and abort in Lindell17 signing finalization |
| Aug 9, 2023 | — | [CVE-2023-33242](https://nvd.nist.gov/vuln/detail/CVE-2023-33242) | BitForge public disclosure at Black Hat USA; CVE-2023-33242 (CVSS 9.1) published; PoC released at [fireblocks-labs/zengo-lindell17-exploit-poc](https://github.com/fireblocks-labs/zengo-lindell17-exploit-poc) |
| Apr 10, 2024 | [silence-laboratories/dkls23](https://github.com/silence-laboratories/dkls23) | [ToB audit report](https://github.com/silence-laboratories/dkls23/blob/main/docs/ToB-SilenceLaboratories_2024.04.10.pdf) | Trail of Bits audit identifies TOB-SILA-12: OT consistency check panics instead of returning identifiable abort; 14 of 15 findings patched |

### Real-World Impact

**BitForge — Lindell17 abort (CVE-2023-33242, August 2023).** This was one of three vulnerabilities in Fireblocks' BitForge disclosure. ZenGo's gotham-city powered a production Bitcoin 2-of-2 MPC wallet with an active user base; Coinbase's WaaS SDK was integrated into multiple third-party mobile wallets. The bit-extraction attack requires only ~200 signing sessions — a threshold easily reachable through normal wallet usage or by an attacker who can induce signing requests. Fireblocks confirmed no wallets were exploited before the patch, and both Coinbase and ZenGo patched before public disclosure.

**MetaMask Silent Shard (2024).** The Silence Laboratories DKLs23 library is the cryptographic engine behind MetaMask's Silent Shard Snap, which provides distributed-key-management (2FA-style protection) for MetaMask users. The TOB-SILA-12 finding means that any user who triggered the OT consistency-check panic — whether through network corruption or a malicious co-signer — would silently lose the ability to distinguish a legitimate abort from an attack. Given that Silent Shard is deployed in a wallet protecting production funds, the key-destruction vector was an unacceptable risk in a production setting. All 14 critical and high findings were patched before the audit report was published.

**Coinbase kryptology deprecation.** The kryptology library was archived in September 2022, shortly after shipping the v1.6.0 and v1.6.1 OT extension fixes. The archive notice means that any downstream project that forked or vendored kryptology before the v1.6.1 patch is permanently on the vulnerable version unless it manually backported the fix. Several open-source projects (e.g., [sei-protocol/coinbase-kryptology](https://github.com/sei-protocol/coinbase-kryptology)) forked the library and may carry the uncorrected consistency check depending on when they forked.

