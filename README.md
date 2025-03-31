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
