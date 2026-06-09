---
title: "Threshold Presignature Reuse (Nonce Reuse)"
class: concurrency-and-state-handling
hidden: false
order: 2
source: "signatures.md"
primitives: [signature]
bugs: [blockdaemon-builder-vault-presignature]
display: [blockdaemon-builder-vault-presignature]
---


**What can go wrong.** ECDSA produces signatures $(r, s)$ where 

$s = k^{-1}(H(m) + r \cdot x) \bmod n$ 

with $k$ a fresh random nonce, $r = (k \cdot G)_x$, and $x$ the
long-term signing key. This equation is linear in $x$ once $k$ and $r$ are fixed, so
reusing the same $k$ across two different messages $m_1 \ne m_2$ produces a pair
$(r, s_1), (r, s_2)$ from which any observer recovers $x$ in closed form: solve
$k = (H(m_1) - H(m_2)) \cdot (s_1 - s_2)^{-1} \bmod n$, then
$x = (s_1 \cdot k - H(m_1)) \cdot r^{-1} \bmod n$. The canonical real-world incident is the 2010 [fail0verflow PlayStation 3 ECDSA break](https://archive.org/details/console-hacking-2010),
where Sony reused a fixed nonce across game-code signatures and the master key fell out of two signed binaries.

Some threshold ECDSA protocols such as [GG18](https://eprint.iacr.org/2019/114),
[GG20](https://eprint.iacr.org/2020/540), and
[CGGMP21](https://eprint.iacr.org/2021/060) generate this nonce distributively as a
*presignature* $(k, R = k \cdot G)$ before the message is known, consuming it once a message arrives. The set of unused presignatures is a stateful object, and implementations must ensure that no two executions consume the same presignature. If they do, two or more signatures share a nonce.

**Security implication.** When two signatures over different messages share a
presignature, anyone who observes them can recover the long-term signing key $x$.
In threshold deployments
the reuse is both easy to trigger and hard to detect: a malicious party can abort a
ceremony after the presignature is fixed and force a retry on a different message,
or route two non-interactive signing requests to different honest subsets using the
same presignature. Honest parties signing non-interactively have no way to notice
that the same nonce is being consumed twice.

**How to avoid.** Atomically (across parallel sessions) consume the presignature
before starting the signing, and consume it whether or not the signing protocol
completed successfully. Upon failure, never retry signing with the same
presignature; generate a fresh one. Beware lifecycle events that can resurrect a
consumed presignature: backup-and-restore, process restarts, snapshots, and
replication must not reintroduce a presignature that has already been used.
