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

### Example

Binance tss-lib's [`ParseWireMessage`](https://github.com/bnb-chain/tss-lib/blob/c84c096da546e9ce9742f9f9cb9e7f06fedc9268/tss/wire.go#L16-L25) accepts an `isBroadcast` flag set entirely by the caller, with no enforcement by the library:

```go
// tss/wire.go — bnb-chain/tss-lib
func ParseWireMessage(wireBytes []byte, from *PartyID, isBroadcast bool) (ParsedMessage, error) {
    wire := new(MessageWrapper)
    wire.IsBroadcast = isBroadcast  // Caller decides — no enforcement
    // ...
}
```

Downstream projects (THORChain, Swingby, Keep Network) deployed tss-lib without implementing reliable broadcast, inheriting the vulnerability directly.

- **Missing session IDs (tss-lib v1.x):** The `ssid` parameter specified in CGGMP21 was never used. The v2.0.0 release notes explicitly list "Add session information for sub protocols to prevent message replay" -- confirming the prior omission. ioFinnet threslib similarly overlooked session IDs (per Arcadia Group analysis).
- **Cascading failures (Multichain fastMPC):** Missing session IDs combined with reduced DLN proof iterations (1 instead of the specified 128) enabled the Verichains TSSHOCK c-guess attack -- full key extraction from a single signing ceremony. Multichain was later compromised with over $130M in stolen funds.

### References

- Aumasson & Shlomovits, ["Attacking Threshold Wallets"](https://eprint.iacr.org/2020/1052.pdf), ePrint 2020/1052.
- Verichains, [TSSHOCK](https://blog.verichains.io/p/tsshock-critical-vulnerabilities), BlackHat USA 2023.
- Arcadia Group, [TSS security analysis](https://blog.arcadia.agency/unveiling-the-secrets-of-binances-tss-adoption-vulnerabilities-and-security-analysis-4c2fd2bf2d9a).
