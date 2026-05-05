---
title: "Missing domain separator across signing contexts"
class: "Lack of Binding to Execution Context"
source: "signatures.md"
---

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
