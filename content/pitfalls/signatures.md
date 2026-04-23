---
title: "Signatures"
class: "Signatures"
order: 8
---

Signature schemes in MPC protocols serve double duty: they authenticate protocol
messages during execution and produce the output signatures that protect user funds.
The two recurring implementation pitfalls are reusing the same signing key across
incompatible protocol roles without a domain-separation tag, and reusing a threshold
presignature (nonce commitment) across two distinct messages — both of which enable
cross-context signature replay or outright key extraction.

### Missing domain separator across signing contexts

**What can go wrong.** When the same signing key is used in multiple protocol roles —
signing round-1 commitments vs round-2 packages in a DKG, authenticating API requests
vs producing blockchain transactions, tagging message types in a single protocol — each
role must prepend a unique, constant-length domain-separation tag to the message
*before* signing. If the tag is missing or identical across roles, a signature produced
for one role is a structurally valid signature for the other: the same bytes verify
against the same key in both contexts. Ed25519's `Sign(key, msg)` default has no context
byte at all; RFC 8032's `Ed25519ctx` variant exists specifically to close this gap but
is opt-in.

**Security implication.** An adversary who obtains a signature in role $A$ presents the
same bytes as if they had been produced for role $B$. In a FROST DKG with a shared
Ed25519 key and no context strings, a malicious party replays a round-1 commitment
signature as a round-2 package signature — the verifier accepts (context is empty, key
is the same) and the replayed commitment corrupts the distributed key share computation.
In multi-role deployments where one identity is used both to authenticate API messages
and to sign blockchain transactions, an authenticated API message becomes replayable as
a transaction signature.

**How to avoid.** Assign a unique, version-bearing domain-separation tag to every
protocol role that consumes signatures, and prepend it to the message before signing.
For Ed25519 use [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)'s `Ed25519ctx` with a
non-empty context per role; for Schnorr or generic hash-then-sign, hash
`tag || message` rather than `message` alone. Rotate tags whenever the protocol version
changes so signatures under the old version do not retroactively validate under a new
role.

**Example: Ed25519 context string left empty.** The default Ed25519 signing primitive
takes only `(key, message)` and produces a signature that carries no role information:

```go
// INSECURE: context left empty — signatures are role-agnostic
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
    return ed25519.Sign(privKey, tagged) // context prepended
}
```

In a FROST DKG where round-1 commitments and round-2 packages are both signed with the
same Ed25519 key and no context string, a malicious party replays a round-1 commitment
signature as a round-2 package signature. The verifier accepts (context is empty, key
is the same) and the replayed commitment corrupts the distributed key share
computation.

### Threshold presignature reuse (nonce reuse)

**What can go wrong.** In GG18/GG20/CGGMP21 threshold ECDSA, the nonce is generated
distributively as a presignature $(k, R = k \cdot G)$ before the message is known. The
ECDSA signing equation $s = k^{-1}(H(m) + r \cdot x) \bmod n$ is linear in the signing
key $x$ once $k$ and $r = R_x$ are fixed. If the same presignature is used for two
different messages $m_1 \ne m_2$, the pair $(r, s_1), (r, s_2)$ leaks $x$: any observer
computes $k = (H(m_1) - H(m_2)) \cdot (s_1 - s_2)^{-1} \bmod n$ and then
$x = (s_1 \cdot k - H(m_1)) \cdot r^{-1} \bmod n$. This is the threshold-setting
analogue of the 2010 PlayStation 3 ECDSA break, where Sony reused a fixed nonce across
game-code signatures and the master key fell out in closed form.

**Security implication.** A single signing party that records its presignature
contribution can retry a signing ceremony twice with different messages, triggering
presignature reuse and extracting the complete signing key $x$. In threshold
deployments even a well-intentioned retry-on-abort path is exploitable: a malicious
party aborts the first ceremony after observing the presignature, forces a retry with a
different message using the same presignature, and walks away with the key. The
Aumasson–Shlomovits
[*Attacking Threshold Wallets*](https://eprint.iacr.org/2020/1052.pdf) paper
catalogues presignature reuse as a first-class threshold-wallet threat.

**How to avoid.** Treat every presignature as single-use. Destroy $(k, R)$ atomically
with the signature output — whether or not the ceremony completed successfully —
before any response is sent. Maintain a signed presignature ledger that marks each
entry as consumed before the response is sent. Never retry a failed signing ceremony
with the same presignature; generate a fresh one.

**Example: presignature object passed twice to `Sign`.** A naïve threshold-ECDSA API
exposes a `Presignature` object and a `Sign(msgHash)` method on it. Calling `Sign`
twice with different message hashes reuses $(k, R)$ and leaks $x$:

```go
// INSECURE: presignature (k, R) not destroyed on Sign; can be reused
type Presignature struct {
    K *big.Int
    R *ECPoint
}

// If Sign is called twice with the same Presignature, the caller (or any observer
// of both signatures) recovers x via the closed-form equations above.
func (p *Presignature) Sign(x, msgHash *big.Int, n *big.Int) *big.Int {
    r := p.R.X
    kInv := new(big.Int).ModInverse(p.K, n)
    return kInv.Mul(kInv, new(big.Int).Add(msgHash, new(big.Int).Mul(r, x)))
}
```

An adversary who participates in two signing sessions that reuse the same $(k, R)$
obtains $(r, s_1)$ and $(r, s_2)$ and solves the system above to extract $x$. The
remediation is to mark the presignature consumed atomically before any response is
returned:

```go
// SECURE: presignature consumed atomically on first use
func (p *Presignature) Sign(x, msgHash *big.Int, n *big.Int) (*big.Int, error) {
    if !p.consumed.CompareAndSwap(false, true) {
        return nil, errors.New("presignature already consumed")
    }
    defer p.Zeroize()  // destroy k before any response is sent
    // ... signing logic ...
}
```

<!--
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
-->
