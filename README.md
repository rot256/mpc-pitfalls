# Common Multi-Party Computation Pitfalls

We are creating a nice collection of common mistakes when implementing MPC protocols. The goal is to help developers avoid these pitfalls and help them implement MPC securely.

## Mistakes

### Commitments are not Bound to the Opening Party

I.e. missing identity information on the sender and session id to ensure that rushing adversaries cannot copy commitments and opening information from other parties.

### Zero Knowledge Proofs not Bound to the Protocol Execution

i.e. not embedding the unique context for the protocol _and_ given execution _and_ constructing party (and potentially receiving party).

### Sequentially Secure Protocol used Concurrently

**Examples:**
- Blind schnorr signatures and ROS.

### Pitfalls for UC protocols
Ensure the following:
- Sessions IDs and sub-session IDs are used for each message to prevent mix-and-match attacks.
- Point-to-Point Channels without Encryption and Authentication.
- Using Multicast Rather than Broadcast i.e. a broadcast channel cannot be instantiated by simply sending the message to all parties.

### Pitfalls for RSA-style moduli

Ensure the following:
- $d>N^{\frac{1}{4}}$.
- Any base element used does have order 2 or 4.

When used in custom protocols it is strongly recommended to ensure the following as well:
- $p$ and $q$ are safe primes.
- $p$ and $q$ are strong primes.
- If the group is used for signatures, then PSS padding is used.
- If the group is used for encryption then OAEP is used.

### Pitfalls for discrete log groups
Ensure the following:
- The group is constructed using a safe prime $p=2q+1$.
- Anything selected by a potentially malicious party (e.g. client) lives in the secure subgroup. I.e. $1 \equiv x^q \mod p$ for $p=2q+1$.
- Any group generator, $g$, is picked to be different from $\pm 1 \mod p$ and $g^{\frac{p-1}{2}} \equiv 1 \mod p$ (to ensure that we are in the subgroup of q elements. Note that this is needed to avoid lsb of exponent being leaked, which happens when using the full group. An alternative approach is to just square everything. See [this paper](https://eprint.iacr.org/2016/995.pdf) for details.

### Pitfalls for elliptic curve groups
Ensure the following:
- The co-factor of the curve is 1 _or_ all base elements are validated to live in the large subgroup.
- Anything selected by a potentially malicious party (e.g. client) is validated to be a valid point on the curve (_not_ infinity) _and_ lives in the large subgroup.
- Hashing to the curve is done algebraically and not just by hashing to a random $x$ coordinate and computing the $y$ coordinate. See [this paper](ttps://eprint.iacr.org/2022/759.pdf) for details.


### Pitfalls for hash functions
Ensure the following:
- If a Merkle-Damgård construction is used (e.g. SHA2), then the application is not vulnerable to extension attacks.
- If a hash function is used in multiple places in a protocol, a unique constant-length domain separator is prepended before hashing a message. 
- If a list is hashed where each element has variable length, hash each element first, and then hash the digests. 

### Pitfalls for signatures
Ensure the following:
- If signing is used in multiple contexts in the protocol then a unique constant-length domain separator is prepended to the message.

### Pitfalls for Fiat-Shamir
Ensure the following:
- The witness domain large enough to not allow for computational brute-forcing.
- Randomness used is computationally large.
