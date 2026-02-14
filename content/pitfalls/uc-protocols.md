---
title: "UC Protocols"
class: "Protocol"
order: 5
---

- Point-to-Point Channels lack Encryption and Authentication.
    - Implementers often hand-roll P2P communication implementations. These hand-rolled implementations often do not have all the desired cryptographic properties that are needed for secure MPC.
- Sessions IDs and sub-session IDs are not used for each message to prevent mix-and-match attacks.
    - Disagreement on session IDs should be detected as soon as possible. If two parties run an OT extension protocol using different session IDs, they might consider each other malicious when the consistency check fails.
- Using Multicast Rather than Broadcast i.e. a broadcast channel cannot be instantiated by simply sending the message to all parties.
    - Even an Echo Broadcast does not provide all desirable properties of a reliable broadcast (as it cannot provide full Byzantine consensus). As an example, the [Forget-and-Forgive attack](https://eprint.iacr.org/2020/1052.pdf) is not prevented by an Echo Broadcast, as the attacker can just move the attack to the second round of the broadcast.
