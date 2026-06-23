---
title: "Unauthenticated or Unencrypted Point-to-Point Channels"
class: insecure-subprotocol-instantiation
hidden: false
order: 2
source: "uc-protocols.md"
primitives: [secure-channel, paillier, homomorphic-encryption]
bugs: [axelar-tofnd-from-field, coinbase-kryptology-gg20-dkg]
display: [axelar-tofnd-from-field, coinbase-kryptology-gg20-dkg]
---


**What can go wrong.** Many MPC protocols such as [GG18](https://eprint.iacr.org/2019/114) and
[GG20](https://eprint.iacr.org/2020/540) assume the presence of *confidential* and *authenticated* P2P channels. The deployment must realize that assumption, typically through mutual TLS,
signed/encrypted application-level messages, or a noise-protocol handshake. Implementations that hand-roll channel security (raw TCP, ad-hoc JSON over HTTP, or implicit trust in a central coordinator that re-signs messages) routinely fail to provide these guarantees.

**Security implication.** Without per-message authentication, a network attacker can
impersonate parties and inject messages honest parties attribute to the wrong source;
the victim of the attribution is then blamed for protocol violations it did not commit.
Without confidentiality, intermediate values that the ideal functionality hides leak to
the network, and downstream secret-dependent computations become vulnerable to offline
analysis. In threshold signing this translates to rogue messages causing spurious
aborts, silent share exposure, and key-extraction attacks that exploit observed
intermediate values.

**How to avoid.** Instantiate the point-to-point channels with "standard secure channel implementations", such as mutual TLS or QUIC between each pair of parties. Ensure that the certificates of each party is pinned or issued by a trusted authority.