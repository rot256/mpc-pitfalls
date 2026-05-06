---
title: "Threshold presignature reuse (nonce reuse)"
class: "Concurrency and Session Lifecycle"
source: "signatures.md"
---

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
