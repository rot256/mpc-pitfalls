---
title: "Blind Schnorr Signatures Used Concurrently (ROS Attack)"
class: others
source: "sequential-used-concurrently.md"
primitives: [signature]
---

### Blind Schnorr Signatures Used Concurrently (ROS Attack)

**What can go wrong.** The blind Schnorr signature scheme is the blind-signature
variant of Schnorr's scheme, in which a requester obtains a signature on a message
of its choice without revealing the message to the signer. This scheme is provably *one-more
unforgeable* in a *single* session
([Pointcheval–Stern, 2000](https://link.springer.com/article/10.1007/s001450010003)):
an adversary that completes $\ell$ signing sessions one at a time cannot output more
than $\ell$ valid signatures. Under *concurrent* signing the property fails:
[Schnorr (2001)](https://link.springer.com/chapter/10.1007/3-540-45600-7_1) gave a
conditional security argument, but it reduces to a hardness conjecture (the *ROS*
problem, introduced below) that turns out not to hold at deployment-relevant
parameters. A signer that
participates in $\ell$ concurrent sessions exposes all nonce commitments $R_i$ to the
requester before it ever commits to the challenges $c_i$. If the requester can choose
all $\ell$ challenges *after* seeing all $R_i$, it can set them to satisfy a linear
relation called the **ROS relation** (*Random inhomogeneities in an Overdetermined
Solvable system of linear equations*) that lets it combine the $\ell$ partial
responses into an $(\ell + 1)$-th, unrequested signature. ROS asks whether an
attacker given $\ell$ random nonce commitments can choose $\ell$ challenges so that
they satisfy an attacker-chosen target linear constraint. Its conjectured hardness
was the security assumption underlying blind Schnorr's original proofs. The same
structural gap applies to naive threshold-Schnorr designs in which each party
contributes a partial nonce and the partial signatures are aggregated without session
binding.

**Security implication.** [Benhamouda et al.](https://link.springer.com/article/10.1007/s00145-021-09417-3)
gave a polynomial-time algorithm for ROS that solves the problem over 256-bit
elliptic-curve groups using approximately $\ell = 192$ concurrent sessions in a matter
of seconds. After collecting responses from those sessions the adversary produces one
extra signature, breaking one-more unforgeability. In threshold-signing deployments,
the same structural gap translates to unauthorized signatures on attacker-chosen
messages after the adversary has collected enough concurrent signing responses.

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



<div class="pitfall-flags"><span class="flag flag-tbd">Schematic only: no public real-world incident found against a deployed implementation</span></div>

**Example: ROS-style concurrent attack on Schnorr signing.** In the blind-signature
setting where [Schnorr (2001)](https://link.springer.com/chapter/10.1007/3-540-45600-7_1)
introduced both the parallel one-more forgery template and the ROS problem at its
core, the vulnerable two-round Schnorr signer accepts challenges from the requester
without any session binding:

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
\mathsf{sk}$, the adversary combines the scalar responses and nonce commitments:
$$k^* = \sum_{i=1}^{\ell} \rho_i k_i,\qquad R^* = k^* G = \sum_{i=1}^{\ell} \rho_i R_i$$
$$s^* = \sum_{i=1}^{\ell} \rho_i s_i = k^* + c^* \cdot \mathsf{sk}$$
yielding a valid signature $(R^*, s^*)$ on a message the signer never individually
signed.

[Drijvers et al.](https://eprint.iacr.org/2018/417.pdf) used the same ROS / $k$-SUM
structure to mount attacks on four two-round Schnorr-based multi-signature schemes:
CoSi, the original 2018 MuSig proposal, BCJ, and MWLD. The shared structural gap is that
the attacker can choose challenges after seeing nonce commitments. That gap appears in
blind Schnorr and in naive threshold-Schnorr designs that aggregate partial signatures
without per-session binding, even though Drijvers et al. analyzed the multi-signature
setting specifically. FROST ([Komlo–Goldberg, 2020](https://eprint.iacr.org/2020/852)) — short for
*Flexible Round-Optimized Schnorr Threshold signatures*, a two-round threshold-Schnorr
signing protocol — uses a per-participant binding-factor design that is the canonical
mitigation against this class of attacks; MuSig2 provides the analogous fix for
multi-signatures. The same session-binding pattern carries back to blind Schnorr: bind
each response to a per-session value derived from the message and nonce commitment, so a
response cannot be linearly combined with one from another session. Schematic
FROST-style mitigation:

```python
# Schematic: FROST-style binding factor prevents cross-session combination
class FROSTSigner:
    def round1(self) -> Point:
        self.hiding_nonce = random_scalar()
        self.binding_nonce = random_scalar()
        self.hiding_commitment = self.hiding_nonce * G
        self.binding_commitment = self.binding_nonce * G
        return (self.hiding_commitment, self.binding_commitment)

    def round2(self, msg: bytes, commitments_list: list[Point],
               participant_index: int) -> Scalar:
        # Binding factor ties this response to the exact (msg, commitment_list, index)
        # tuple. A response from a different session has a different rho and cannot
        # be linearly combined with this one.
        rho = H(msg, commitments_list, participant_index)   # binding factor
        R_agg = compute_group_commitment(commitments_list, msg)
        c = H(R_agg, msg)                                  # Fiat-Shamir challenge
        lambda_i = derive_interpolating_value(commitments_list, participant_index)

        s = self.hiding_nonce + rho * self.binding_nonce + lambda_i * c * self.sk
        return s
```
