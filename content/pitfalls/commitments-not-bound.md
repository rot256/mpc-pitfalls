---
title: "Commitments Are Not Bound to the Opening Party"
class: "Protocol"
order: 2
---

In many MPC protocol, for instance, commit-and-reveal, it's important to bind the commitments to a particular party,
such that e.g. a rushing adversaries which can observe honest parties commitments,
before providing his own, cannot copy commitments of an honest party.
As a toy example consider a simple Blum coinflip protocol:

1. Alice commits to `v_alice` by sending `com_alice = Com(v_alice; r_alice)`
1. Bob commits to `v_bob` by sending `com_bob = Com(v_bob; r_bob)`
1. After each party receives a commitment, they both open:
  - Alice sends `v_alice`, `r_alice` to Bob
  - Bob sends `v_bob`, `r_bob` to Alice
1. They both compute `v_alice XOR v_bob` as the output of the coinflip

This simple protocol is vulnable to an attack, because the commitments of either party is not bound to the party.
A corrupt Bob can force the coinflip to always be `0` as follows:

1. Alice sends `com_alice` to Bob.
1. Bob sets `com_bob = com_alice` and sends this as his commitment to Alice
1. Both commitments are opened to `v_alice` and the output is `v_alice XOR v_alice = 0`

### Example

In the [SPDZ protocol](https://eprint.iacr.org/2011/535.pdf),
the parties have BDOZ MACs on all wires in the circuit.
For an additively secret shared value $a$, 
a BDOZ MAC consists of a secret sharing of $[\alpha \cdot a]$ where $\alpha$ is a global MAC key.
To verify that the parties have reconstructed the correct $a'$ (i.e. $a = a'$ if all parties are honest), they compute:
$$
[z] = a' \cdot [\alpha] - [\alpha \cdot a]
$$
And want to check that $z = 0$.
To do this, they each commit to their share $z_i$ and reconstructs $z$.
If $z$ is non-zero they all abort the protocol.

Consider the following code from [Fresco](https://github.com/aicis/fresco/commit/fdada93b1abf19c68a1cf744e0f294df86bb1b8f)

```java
// FILE: SpdzMacCheckProtocol.java

...

// compute gamma_i as the sum of all MAC's on the opened values times
// r_j.
FieldElement gamma = definition.createElement(0);
index = 0;
for (SpdzSInt closedValue : closedValues) {
  FieldElement closedValueHidden = rs[index++].multiply(closedValue.getMac());
  gamma = gamma.add(closedValueHidden);
}

// compute delta_i as: gamma_i - alpha_i*a
FieldElement delta = gamma.subtract(alpha.multiply(a));
byte[] deltaBytes = definition.serialize(delta);

// Commit to delta and open it afterwards
return seq.seq(new CommitmentComputation(commitmentSerializer, deltaBytes, localDrbg));

...

// FILE: HashBasedCommitment.java‎
public byte[] commit(Drbg rand, byte[] value) {
   if (commitmentVal != null) {
     throw new IllegalStateException("Already committed");
   }
   // Sample a sufficient amount of random bits
   byte[] randomness = new byte[DIGEST_LENGTH];
   rand.nextBytes(randomness);
   // Construct an array to contain the bytes to hash
   byte[] openingInfo = new byte[value.length + randomness.length];
   System.arraycopy(value, 0, openingInfo, 0, value.length);
   System.arraycopy(randomness, 0, openingInfo, value.length)
   commitmentVal = digest.digest(openingInfo);
   return openingInfo;
}
```

In other words, each party computes their commitment as $c_i = \mathsf{Hash}(z_i |\!| r_i)$.

**Attack.**
Suppose for simplicity that the protocol operates over $\mathbb{F}_{2^k}$ and there are two parties,
of which one is corrupt.
The attack is executed by the corrupt party by simply copying the commitment of the honest party,
then during the reveal, copying the opening of the honest party. This causes:

$$
z_1 + z_1 = 0
$$

And the MAC-check passes, regardless of what $a'$ was reconstructed.
