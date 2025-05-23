# Common Multi-Party Computation Pitfalls

We are creating a nice collection of common mistakes when implementing MPC protocols. The goal is to help developers avoid these pitfalls and help them implement MPC securely.

## Mistakes

### Pitfall: Commitments are not Bound to the Opening Party

I.e. missing identity information on the sender and session id to ensure that rushing adversaries cannot copy commitments and opening information from other parties.

### Pitfall: Zero Knowledge Proofs not Bound to the Protocol Execution

i.e. not embedding the unique context for the protocol _and_ given execution _and_ constructing party (and potentially receiving party).

### Pitfall: Sequentially Secure Protocol used Concurrently

**Examples:**
- Blind schnorr signatures and ROS.

### Pitfall: Sequentially Secure Protocol used Concurrently

**Examples:**
- Concurrent SPDZ MAC check without appropriate synchronization. To be secure in the presence of multi-threading, the whole MAC check subprotocol needs to be treated as critical section, including the possible abort.

Note that the term "concurrent" is overloaded: It can refer to concurrency in a distributed system (standard in the MPC literature, including UC), or concurrency in the sense of multi-threading/cooperative multi-tasking etc (not covered by standard security models). A multi-threaded MPC implementation might need concurrent security in both meanings of the word.

### Pitfalls: UC protocols
- Point-to-Point Channels lack Encryption and Authentication.
- Sessions IDs and sub-session IDs are not used for each message to prevent mix-and-match attacks.
- Using Multicast Rather than Broadcast i.e. a broadcast channel cannot be instantiated by simply sending the message to all parties.

### Pitfalls: RSA-style moduli
- Not validating that the private key $d>N^{\frac{1}{4}}$.
- Not validating that a base element has order 2 or 4.

#### Recommendations:
When used in custom protocols it is strongly recommended to ensure the following as well:
- $p$ and $q$ are safe primes.
- $p$ and $q$ are strong primes.
- If the group is used for signatures, then PSS padding is used.
- If the group is used for encryption then OAEP is used.

### Pitfall: Discrete log groups
- The group is not defined from a safe prime $p=2q+1$.
- Anything, $x$, selected by a potentially malicious party (e.g. client) is not validated to live in the secure subgroup before usage. I.e. $1 \equiv x^q \mod p$ for $p=2q+1$.
- Missing validation that any group generator $g$ is different from $\pm 1 \mod p$ and $g^{\frac{p-1}{2}} \equiv 1 \mod p$. (This is needed to ensure that elements live in the subgroup of q elements. Note that this is needed to avoid lsb of exponent being leaked, which happens when using the full group. An alternative approach is to just square everything. See [this paper](https://eprint.iacr.org/2016/995.pdf) for details.)

### Pitfalls: Elliptic curve groups
- Not ensuring that the co-factor of the curve is 1 _or_ all base elements are validated to live in the large subgroup.
- Anything selected by a potentially malicious party (e.g. client) is not validated to be a valid point on the curve (_not_ infinity) _and_ potentially living in the large subgroup in case of co-factor different from 1.
- Not using a curve hashing algorithm for hashing to the curve. That is, hashing an element to a random $x$ coordinate and computing the $y$ coordinate is likely not going to be secure. See [this paper](ttps://eprint.iacr.org/2022/759.pdf) for details.


### Pitfalls: Hash functions
- If a Merkle-Damgård construction is used (e.g. SHA2), not validating that the application is not vulnerable to extension attacks.
- When a hash function is used in multiple places in a protocol, not adding a unique constant-length domain separator. 
- When a list is hashed where each element has variable length, not hashing each element independently, and then hashing the digests together. 

### Pitfalls: Signatures
- Not prepending a unique constant-length domain separator to the message when signing keys are used in different contexts.

### Pitfalls: Fiat-Shamir
- The witness domain is not large enough to not allow for computational brute-forcing, i.e. has less than 128 bits of entropy.
- Randomness used does not contain at least 128 bits of entropy.

### Improper input checks

It is often the case that the "secret space" differs from the "share space".
This is for example the case when using Shamir's secret sharing over a small field such as `F_2`, or a ring such as `Z_2^64`.
This is (arguably) also the case for protocols that rely on statistical hiding.
If the input mechanism of the secure protocol does not validate an input, it might lead to incorrect computations and/or breaches of privacy.
