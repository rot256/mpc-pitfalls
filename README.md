# Common Multi-Party Computation Pitfalls

We are creating a nice collection of common mistakes when implementing MPC protocols. The goal is to help developers avoid these pitfalls and help them implement MPC securely.

## Mistakes

### Point-to-Point Channels without Encryption

### Using Multicast Rather than Broadcast

i.e. a broadcast channel cannot be instantiated by simply sending the message to all parties.

### Commitments are not Bound to the Opening Party

### Zero Knowledge Proofs not Bound to the Protocol Execution

### Sequentially Secure Protocol used Concurrently

**Examples:**
- Blind schnorr signatures and ROS.

### Improper input checks

It is often the case that the "secret space" differs from the "share space".
This is for example the case when using Shamir's secret sharing over a small field such as `F_2`, or a ring such as `Z_2^64`.
This is (arguably) also the case for protocols that rely on statistical hiding.
If the input mechanism of the secure protocol does not validate an input, it might lead to incorrect computations and/or breaches of privacy.
