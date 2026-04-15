---
title: "Signatures"
class: "Cryptographic Primitive"
order: 10
---

- Not prepending a unique constant-length domain separator to the message when signing keys are used in different contexts.

---

# DRAFT Signatures

Signature schemes in MPC protocols serve double duty: they authenticate protocol messages during execution and produce the output signatures that protect user funds. A recurring failure is using the same key — or the same proof context — across multiple incompatible protocol sessions without binding each to a unique session identifier. Without this binding, a ZK proof or partial signature produced in one session is structurally valid in any other, enabling cross-session replay attacks.

### Example 1: SSID Hardcoded to Zero Across All Sessions — CVE-2022-47930

CGGMP21 and GG18/GG20 protocols require every sub-protocol ZK proof to include a **session sub-ID** (`ssid`) in its Fiat-Shamir hash. In tss-lib v1.x, the `ssidNonce` used to derive the SSID was hardcoded to `0` in every signing, keygen, and resharing round. This made the SSID identical across all protocol executions: a Schnorr proof, range proof, or modulus proof generated in session $A$ was indistinguishable from one in session $B$.

([source](https://github.com/bnb-chain/tss-lib/commit/fc38979249))

```go
// ecdsa/signing/round_1.go — bnb-chain/tss-lib v1.x (vulnerable, CVE-2022-47930)
// ssidNonce hardcoded to 0 — every session produces the same SSID.
// A ZK proof from session A is structurally valid in session B.
round.temp.ssidNonce = new(big.Int).SetUint64(0)
ssid, err := round.getSSID()
// getSSID() hashes pubkey, party IDs, and ssidNonce.
// With ssidNonce = 0 in every session, all SSIDs are identical.
```

The same hardcoded zero appeared in `ecdsa/keygen/round_1.go`, `ecdsa/resharing/round_1_old_step_1.go`, `eddsa/keygen/round_1.go`, and `eddsa/signing/round_1.go`.

**Attack.** Party $P_i$ generates a Schnorr proof $\pi$ during keygen session $A$. In signing session $B$, an adversary replays $\pi$ as its own round-2 contribution. Because the SSID is $0$ in both sessions, the challenge hash is identical and the proof passes verification. This allows the adversary to avoid computing an honest partial signature, breaking output correctness. The same replay applies to range proofs (MtA) and modulus proofs.

**Remediation.** Commit [`fc38979249`](https://github.com/bnb-chain/tss-lib/commit/fc38979249) derived the SSID from the message hash (for signing) or a caller-provided nonce:

([source](https://github.com/bnb-chain/tss-lib/commit/fc38979249))

```go
// ecdsa/signing/round_1.go — bnb-chain/tss-lib v2.0.0 (fixed)
if nonce := round.Params().SessionNonce(); nonce != nil {
    round.temp.ssidNonce = new(big.Int).Set(nonce)
} else {
    round.temp.ssidNonce = new(big.Int).Set(round.temp.m) // message hash for signing
}
ssid, err := round.getSSID() // now unique per session
```

A complementary fix ([commit `b59ed365b0`](https://github.com/bnb-chain/tss-lib/commit/b59ed365b0)) switched all proof hashes to `SHA512_256i_TAGGED(Session, ...)`, adding the session tag as a domain separator directly inside the Fiat-Shamir hash.

### Example 2: Ed25519 / Schnorr Context String Left Empty

EdDSA (Ed25519) supports an optional context string in the hash. Many implementations leave the context empty by default. When the same Ed25519 key is used in two protocol roles without distinct context strings, signatures are interchangeable between roles.

([source](https://www.rfc-editor.org/rfc/rfc8032))

```go
// INSECURE: context left empty — signatures are context-agnostic
func signInsecure(privKey ed25519.PrivateKey, msg []byte) []byte {
    return ed25519.Sign(privKey, msg) // uses empty context
}

// SECURE: distinct context strings prevent cross-role replay
const (
    ctxDKGRound1  = "frost-dkg-round1-v1"
    ctxThreshSign = "frost-signing-v1"
)

func signWithContext(privKey ed25519.PrivateKey, ctx string, msg []byte) []byte {
    tagged := append([]byte(ctx), msg...)
    return ed25519.Sign(privKey, tagged) // manually prefixed
}
```

**Attack.** In a FROST DKG where round-1 commitments and round-2 packages are signed with the same Ed25519 key and no context string, a malicious party replays a round-1 commitment signature as a round-2 package signature. The verifier accepts — context is empty, the key is the same — and the replayed commitment corrupts the distributed key share computation.

**Remediation.** Assign a unique, version-bearing context string to every protocol role that requires signatures. Rotate context strings when the protocol version changes.

### Example 3: Threshold Presignature Reuse

In GG18/GG20 threshold ECDSA, the presignature $(k, R = k \cdot G)$ is computed in a distributed ceremony before the message is known. If the same presignature is used for two different messages $m_1$ and $m_2$, the private key $x$ is recoverable from both signatures:

$$k = (H(m_1) - H(m_2)) \cdot (s_1 - s_2)^{-1} \bmod n, \quad x = (s_1 \cdot k - H(m_1)) \cdot r^{-1} \bmod n$$

([source](https://eprint.iacr.org/2020/1052.pdf))

```go
// INSECURE: presignature (k, R) reused across two signing calls
type Presignature struct {
    K *big.Int
    R *ECPoint
}

// If Sign is called twice with the same Presignature, the caller can recover x.
func (p *Presignature) Sign(x, msgHash *big.Int, n *big.Int) *big.Int {
    r := p.R.X
    kInv := new(big.Int).ModInverse(p.K, n)
    return kInv.Mul(kInv, new(big.Int).Add(msgHash, new(big.Int).Mul(r, x)))
}
```

**Attack.** An adversary who participates in two signing sessions that reuse the same $(k, R)$ obtains $(r, s_1)$ and $(r, s_2)$ and solves the system of equations above to extract $x$. In threshold settings, a single corrupt party that records its presignature contribution can later supply identical partial values to force presignature reuse across sessions.

**Remediation.** Treat every presignature as single-use: destroy $(k, R)$ atomically with the signature output, whether or not the ceremony completed successfully. Maintain a signed presignature ledger that marks each entry as consumed before the response is sent. Never retry a failed signing ceremony with the same presignature.

### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| 2010 | Sony PlayStation 3 | — | ECDSA nonce reuse ($k$ constant across signatures) allows full private key recovery |
| 2018 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | Initial release | `ssidNonce` hardcoded to 0 in all keygen, signing, resharing, and EdDSA rounds |
| 2020 | Aumasson & Shlomovits | [eprint 2020/1052](https://eprint.iacr.org/2020/1052.pdf) | Presignature reuse and cross-session proof replay documented as threshold wallet attacks |
| Dec 2022 | io.Finnet | [CVE-2022-47930](https://nvd.nist.gov/vuln/detail/CVE-2022-47930) | SSID=0 disclosed; proof replay across sessions; affects tss-lib v1.x and IoFinnet threshlib |
| 2021 | IETF | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | Ed25519ctx context parameter standardised; empty context noted as insecure for multi-role keys |
| Aug 23, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [commit `fc38979249`](https://github.com/bnb-chain/tss-lib/commit/fc38979249) | Fix: `ssidNonce` derived from message hash or caller-provided nonce |
| Aug 26, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | v2.0.0 | Session-tagged proof hashes (`SHA512_256i_TAGGED`) shipped; not backward-compatible with v1.x |

### Real-World Impact

**CVE-2022-47930 — IoFinnet / tss-lib ecosystem (December 2022).** The SSID=0 vulnerability was disclosed by io.Finnet in December 2022 (CVSS 8.8 High). It affected all tss-lib v1.x deployments: any threshold ECDSA or EdDSA signing ceremony allowed proof replay across sessions. THORChain halted its mainnet in March 2023 after receiving Verichains' TSSHOCK proof of concept, which relied on the missing session binding among other weaknesses. All downstream forks (SwingBy, Keep Network, Multichain) running v1.x inherited the exposure. The v2.0.0 fix is not backward-compatible: parties on v1.x and v2.0.0 cannot interoperate, creating a mixed-version rollout risk that incentivised operators to delay upgrading.

**Presignature reuse (recurring).** The 2010 PlayStation 3 break — two ECDSA signatures sharing the same nonce $k$ — is the canonical nonce-reuse example: the private key is recovered in closed form. In threshold ECDSA, the distributed presignature plays the same role. The Aumasson–Shlomovits paper identified presignature reuse as a first-class threshold wallet threat; subsequent audits (Kudelski, Trail of Bits) explicitly checked for absence of presignature-reuse protection.
