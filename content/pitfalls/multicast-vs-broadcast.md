---
title: "Improper Use of Multicast"
class: "Protocol"
order: 16
---

- A broadcast channel cannot be instantiated by simply sending the message to all parties (multicast), as this does not ensure that all honest parties receive the same message.
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

### References

- Aumasson & Shlomovits, ["Attacking Threshold Wallets"](https://eprint.iacr.org/2020/1052.pdf), ePrint 2020/1052.
