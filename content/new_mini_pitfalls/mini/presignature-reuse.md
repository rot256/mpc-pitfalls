---
title: "Threshold Presignature Reuse (Nonce Reuse)"
class: "Concurrency and State Handling"
order: 2
source: "signatures.md"
---

### Threshold Presignature Reuse (Nonce Reuse)

**What can go wrong.** ECDSA produces signatures $(r, s)$ where 

$s = k^{-1}(H(m) + r \cdot x) \bmod n$ 

with $k$ a fresh random nonce, $r = (k \cdot G)_x$, and $x$ the
long-term signing key. This equation is linear in $x$ once $k$ and $r$ are fixed, so
reusing the same $k$ across two different messages $m_1 \ne m_2$ produces a pair
$(r, s_1), (r, s_2)$ from which any observer recovers $x$ in closed form: solve
$k = (H(m_1) - H(m_2)) \cdot (s_1 - s_2)^{-1} \bmod n$, then
$x = (s_1 \cdot k - H(m_1)) \cdot r^{-1} \bmod n$. The canonical real-world
incident is the 2010
[fail0verflow PlayStation 3 ECDSA break](https://archive.org/details/console-hacking-2010),
where Sony reused a fixed nonce across game-code signatures and the master key fell
out of two signed binaries.

Modern threshold-ECDSA protocols such as [GG18](https://eprint.iacr.org/2019/114),
[GG20](https://eprint.iacr.org/2020/540), and
[CGGMP21](https://eprint.iacr.org/2021/060) generate this nonce distributively as a
*presignature* $(k, R = k \cdot G)$ before the message is known, consuming it once a
message arrives. The presignature exists as a stateful object that can in principle
be referenced more than once, so two signing ceremonies that consume the same
presignature reproduce the single-party nonce-reuse failure: any observer (including
any signing participant) recovers $x$ from the resulting pair of signatures.

**Security implication.** A single signing party that records its presignature
contribution can retry a signing ceremony twice with different messages, triggering
presignature reuse and extracting the complete signing key $x$. In threshold
deployments the failure surface widens: a malicious party can abort the first
ceremony after observing the presignature and force a retry with a different message;
or, exploiting the non-interactive nature of online signing, orchestrate two signing
requests with different honest subsets using the same presignature ID. As a result, honest
parties signing non-interactively cannot detect that the same nonce is being consumed
twice. Lifecycle hazards compound this: backup-and-restore can reintroduce a
previously-consumed presignature, and any reuse-by-ID after a process restart,
snapshot, or replication event has the same effect. The Aumasson–Shlomovits
[*Attacking Threshold Wallets*](https://eprint.iacr.org/2020/1052.pdf) paper
catalogues presignature reuse as a first-class threshold-wallet threat.

**How to avoid.** Treat every presignature as single-use. Destroy $(k, R)$ atomically
with the signature output (whether or not the ceremony completed successfully)
before any response is sent. Maintain a signed presignature ledger that marks each
entry as consumed before the response is sent. Never retry a failed signing ceremony
with the same presignature; generate a fresh one.

**Example: Blockdaemon Builder Vault warns against 2-of-3 presignature reuse
([Builder Vault TSM docs](https://builder-vault-tsm.docs.blockdaemon.com/docs/presignatures)).**
Builder Vault is Blockdaemon's production MPC threshold-signing platform (powered by
the Sepior TSM). Its developer documentation explains that each presignature contains
shares of a random signing nonce, and that an MPC node enforces single-use by
deleting the presignature in the same transaction in which it consumes its share.
The docs additionally warn that backup-and-restore can reintroduce a
previously-consumed presignature, turning a routine ops procedure into a
key-extraction vector if mishandled. Operators are therefore instructed to delete
all presignatures either before taking a database backup or upon restoring.
