---
title: "Blind Schnorr signatures used concurrently (ROS attack)"
class: "Concurrency and Session Lifecycle"
source: "sequential-used-concurrently.md"
---

### Blind Schnorr signatures used concurrently (ROS attack)

**What can go wrong.** The blind Schnorr signature scheme is provably one-more
unforgeable in a *single* session but not under concurrent signing. A signer that
participates in $\ell$ concurrent sessions exposes all nonce commitments $R_i$ to the
requester before it ever commits to the challenges $c_i$. If the requester can choose
all $\ell$ challenges *after* seeing all $R_i$, it can set them to satisfy a linear
relation (the ROS relation) that lets it combine the $\ell$ partial responses into an
$(\ell + 1)$-th, unrequested signature. The same structural gap broke early threshold
Schnorr designs in which each party contributes a partial nonce and the partial
signatures are aggregated without session binding.

**Security implication.** [Benhamouda et al.](https://link.springer.com/article/10.1007/s00145-021-09417-3)
gave a polynomial-time algorithm for ROS that solves the problem over 256-bit
elliptic-curve groups using approximately $\ell = 192$ concurrent sessions in a matter
of seconds. After collecting responses from those sessions the adversary produces one
extra signature — breaking one-more unforgeability. In threshold-signing deployments
this translates directly to unauthorised signatures on attacker-chosen messages: keys
that were supposed to require threshold cooperation can be used to sign arbitrary
payloads.

**How to avoid.** Two complementary approaches.

*Structural.* Bind each challenge to the session's specific nonce commitment and
message so the adversary cannot freely choose challenges after observing the nonces.
FROST achieves this with a per-participant binding factor, standardized in
[RFC 9591](https://datatracker.ietf.org/doc/html/rfc9591) (June 2024). MuSig2
([Nick et al., CRYPTO 2021](https://eprint.iacr.org/2020/1261)) uses two aggregated
nonces per session whose specific linear combination is provably secure under
concurrent execution.

*Application-layer serialisation.* If the protocol itself cannot be changed, the signer
must complete or abort one session before starting another, preventing the
$\ell \approx 192$ sessions required to solve ROS from being open simultaneously.

**Example: Drijvers et al. concurrent attack on two-round multi-signatures.** The
vulnerable two-round blind Schnorr signer accepts challenges from the requester without
any session binding:

```python
# Vulnerable blind Schnorr signer — no binding between nonce and challenge
class BlindSchnorrSigner:
    def round1(self) -> Point:
        self.k = random_scalar()          # fresh nonce per session
        self.R = self.k * G               # nonce commitment
        return self.R                     # sent to requester

    def round2(self, c: Scalar) -> Scalar:
        # c arrives from the requester with no proof it was derived from
        # this specific R or from any particular message.
        # A malicious requester can choose c freely — including as a
        # linear combination of challenges from other concurrent sessions.
        s = self.k + c * self.sk          # partial response
        return s
```

The requester accumulates $\ell$ sessions. In each session $i$ it receives $R_i$ from the
signer, then chooses all $\ell$ challenges *jointly* so they satisfy the ROS relation
$\sum_{i=1}^{\ell} \rho_i \cdot c_i = c^* \pmod{q}$ for a target challenge $c^*$ and
known coefficients $\rho_i$. After collecting $\ell$ responses $s_i = k_i + c_i \cdot
\mathsf{sk}$, the adversary combines them:
$$s^* = \sum_{i=1}^{\ell} \rho_i \cdot s_i = \sum \rho_i k_i + \left(\sum \rho_i c_i\right) \mathsf{sk} = R^* + c^* \cdot \mathsf{sk}$$
yielding a valid signature $(R^*, s^*)$ on a message the signer never individually
signed. [Drijvers et al.](https://eprint.iacr.org/2018/417.pdf) showed that early
threshold Schnorr protocols — where each party contributes a partial nonce and the
partial signatures are aggregated without session binding — break under the same attack.
This directly affected the original design of FROST prior to round 2 of the IETF
standardization process. The fix:

```python
# Fixed: FROST-style binding factor prevents cross-session combination
class FROSTSigner:
    def round1(self) -> Point:
        self.k = random_scalar()
        self.R = self.k * G
        return self.R

    def round2(self, msg: bytes, commitments_list: list[Point],
               participant_index: int) -> Scalar:
        # Binding factor ties this response to the exact (msg, commitment_list, index)
        # tuple. A response from a different session has a different rho and cannot
        # be linearly combined with this one.
        rho = H(msg, commitments_list, participant_index)   # binding factor
        R_agg = sum(rho_j * R_j for rho_j, R_j in zip(rhos, commitments_list))
        c = H(R_agg, msg)                                  # Fiat-Shamir challenge

        s = self.k + rho * c * self.sk    # response bound to this session only
        return s
```
