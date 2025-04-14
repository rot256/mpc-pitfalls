# Common Multi-Party Computation Pitfalls

We are creating a nice collection of common mistakes when implementing MPC protocols. The goal is to help developers avoid these pitfalls and help them implement MPC securely.

## Mistakes

### Pitfall: Improper verification of received messages

In MPC protocols, parties exchange mathematical objects such as 'an element from $\mathbb{Z}_q^*$', 'a commitment to the coefficients of a degree $t-1$ polynomial', or 'a list of zero-knowledge proofs'. In MPC implementations, parties exchange bitstrings over a network, and they need to verify that the received bitstring corresponds to a valid mathematical object of the expected type. Each of the following issues is commonly found in MPC implementations, affecting confidentiality, integrity, or availability:
- **The received value is not a valid element**: When receiving an element from $\mathbb{Z}_q^*$ or a similar group/ring/field, the receiver needs to check that it's non-zero. Additionally, when the element is supposed to generate a non-trivial subgroup, the receiver also needs to check that it's not 1 (or some other invalid value that does not generate the correct subgroup).
- **The received sequence of values is not the correct length**: 
    - When receiving the commitments to the coefficients of a degree $t-1$ polynomial during Feldman VSS, the receiver needs to check that the length of the committed coefficient vector is equal to $t$, lest the threshold becomes higher than intended.
    - When receiving a list of zero-knowledge proofs, the receiver needs to verify that the list is not empty. Iterating over an empty list often results in accepting the proofs, as an empty list contains no incorrect proofs.

### Pitfall: Commitments are not Bound to the Opening Party

I.e. missing identity information on the sender and session id to ensure that rushing adversaries cannot copy commitments and opening information from other parties.

### Pitfall: Zero Knowledge Proofs not Bound to the Protocol Execution

i.e. not embedding the unique context for the protocol _and_ given execution _and_ constructing party (and potentially receiving party).

### Pitfall: Sequentially Secure Protocol used Concurrently

**Examples:**
- Blind schnorr signatures and ROS.

### Pitfalls: UC protocols
- Point-to-Point Channels lack Encryption and Authentication.
    - Implementers often hand-roll P2P communication implementations. These hand-rolled implementations often do not have all the desired cryptographic properties that are needed for secure MPC. 
- Sessions IDs and sub-session IDs are not used for each message to prevent mix-and-match attacks.
    - Disagreement on session IDs should be detected as soon as possible. If two parties run an OT extension protocol using different session IDs, they might consider each other malicious when the consistency check fails. 
- Using Multicast Rather than Broadcast i.e. a broadcast channel cannot be instantiated by simply sending the message to all parties.
    - Even an Echo Broadcast does not provide all desirable properties of a reliable broadcast (as it cannot provide full Byzantine consensus). As an example, the [Forget-and-Forgive attack](https://eprint.iacr.org/2020/1052.pdf) is not prevented by an Echo Broadcast, as the attacker can just move the attack to the second round of the broadcast.

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
    - Alternatively, ensure correct list hashing by prepending the length of each element

### Pitfalls: Signatures
- Not prepending a unique constant-length domain separator to the message when signing keys are used in different contexts.

### Pitfalls: Fiat-Shamir
- The witness domain is not large enough to not allow for computational brute-forcing, i.e. has less than 128 bits of entropy.
- Randomness used does not contain at least 128 bits of entropy.
- The transcript used to generate challenges does not include all required values, including but not limited to the public input and the problem statement ([weak Fiat-Shamir](https://eprint.iacr.org/2020/1052.pdf)). 

### Improper input checks

It is often the case that the "secret space" differs from the "share space".
This is for example the case when using Shamir's secret sharing over a small field such as `F_2`, or a ring such as `Z_2^64`.
This is (arguably) also the case for protocols that rely on statistical hiding.
If the input mechanism of the secure protocol does not validate an input, it might lead to incorrect computations and/or breaches of privacy.

### Pitfalls: Shamir Secret Sharing
- Some implementations let parties choose their own index. By choosing index $0$ or $0\mod p$, a malicious party can get the other parties to send their secret contribution.

### Pitfalls: Feldman Verified Secret Sharing: 
- If parties do not check the length of the verification values, a malicious party can send a longer vector (which corresponds to a higher-degree polynomial). They can use this to [surreptitiously raise the threshold](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/), preventing honest users from using the key.
- Rogue key attacks: if at least one of the following mitigations is not implemented, a malicious party can fix the shared private key to one that they know after seeing the inputs of all other parties:
    - Force all parties to commit to their inputs before revealing anything
    - Force parties to prove knowledge of their secret contributions (in zero knowledge)

### Pitfalls: Oblivious Transfer
- Many oblivious transfer extension protocols rely on consistency checks to get active security. However, they suffer from selective abort attacks, where succeeding or failing a consistency check leaks a few bits of information on the underlying OT secret. As a result, reusing the base OT secrets for multiple OT extension protocols is dangerous.
    - [DKLs23](https://eprint.iacr.org/2023/765.pdf) states that an abort during OT extension requires the involved party to abort all instances of the protocol running in parallel that involve the offending party. This is extremely difficult to guarantee from an engineering standpoint.

