---
title: "Concurrent Signing Sessions (ROS Attack)"
class: concurrency-and-state-handling
hidden: false
order: 3
source: "sequential-used-concurrently.md"
primitives: [signature]
---

**What can go wrong.** Many signature schemes rely on linear structures, and when run
sequentially they are proven secure: blind Schnorr, for instance, is one-more unforgeable
in the sequential setting ([Pointcheval–Stern, 2000](https://link.springer.com/article/10.1007/s001450010003)),
and the GJKR threshold Schnorr scheme is proven secure in a stand-alone sequential setting
([GJKR07](https://link.springer.com/article/10.1007/s00145-006-0347-3)). The reason is that
each session finishes before the next one starts, so partial signatures from different
sessions can never be combined. Under concurrent execution, though, their security comes to
rest on the hardness of the **ROS problem** (_Random inhomogeneities in an Overdetermined
Solvable system of linear equations_): [Schnorr (2001)](https://link.springer.com/chapter/10.1007/3-540-45600-7_1)
could establish blind Schnorr's concurrent security only by reducing it to ROS hardness.
And ROS, it turns out, is not hard. [Benhamouda et al.](https://eprint.iacr.org/2020/945)
gave an efficient algorithm that solves it, letting an attacker forge signatures in exactly
these settings.

The shared structure is this. Across $\ell$ concurrent sessions a forger collects nonce
commitments $R_i$ and responses $s_i = k_i + c_i x$, then combines them with coefficients
$\rho_i$:

$$
R^* = \sum_{i=1}^{\ell} \rho_i R_i, \qquad
s^* = \sum_{i=1}^{\ell} \rho_i s_i = \Big(\sum_i \rho_i k_i\Big) + \Big(\sum_i \rho_i c_i\Big) x.
$$

The pair $(R^*, s^*)$ is a valid signature on a fresh message $m^*$ exactly when the
challenges satisfy the **ROS relation**
$$\sum_{i=1}^{\ell} \rho_i c_i = c^* = H(R^*, m^*).$$
Sequentially the forger never holds all the $R_i$ at once, so it cannot pick challenges to
satisfy this; concurrency is what exposes every $R_i$ before the challenges are fixed and
hands it the free variables. The three schemes differ only in who steers the $c_i$:

- **Blind Schnorr.** The signer returns $s_i = k_i + c_i x$ to whatever challenge it is
  handed, and the requester _sends_ the $c_i$, so it sets them directly to solve the ROS
  relation.
- **GJKR threshold Schnorr.** The challenge is $c_i = H(R_i, m_i)$ over a jointly generated
  nonce $R_i = \sum_j R_{i,j}$, and each honest party returns a partial
  $s_{i,j} = k_{i,j} + c_i \lambda_j x_j$ (with Lagrange coefficient $\lambda_j$ and share
  $x_j$). A _rushing_ corrupt party chooses its own share $R_{i,n}$ after seeing the honest
  ones, so it controls every $R_i$, hence every $c_i$, across the concurrent sessions.
  GJKR's security proof reached only the non-concurrent setting, or up to a logarithmic
  number of concurrent sessions, so this high-concurrency path lies outside what it ever
  guaranteed.
- **Original FROST.** Structurally the same, with a single un-bound nonce $D_{i,j}$ per
  party and partial $z_{i,j} = d_{i,j} + c_i \lambda_j x_j$. The July 2020 revision closes
  it by adding a second nonce $E_{i,j}$ and a per-participant binding factor
  $b_j = H(j, m, B)$ over the whole commitment list $B$, so the group nonce becomes
  $R_i = \sum_j (D_{i,j} + b_j E_{i,j})$. Every challenge now depends on $B$ through the
  $b_j$, the $c_i$ can no longer be lined up across sessions, and the ROS relation cannot be
  set up.

**Security implication.** Concretely, that algorithm solves ROS over a 256-bit
elliptic-curve group with about $\ell = 256$ concurrent sessions in seconds
([Benhamouda et al.](https://eprint.iacr.org/2020/945)): the adversary combines the
responses it has collected and outputs one signature more than it was granted, breaking
one-more unforgeability. The significance varies by primitive. For multi-signatures that
claimed concurrent security (the 2018 MuSig, CoSi) it breaks those claims outright; for
threshold signatures like GJKR, whose proofs covered only the non-concurrent or
bounded-concurrency setting, it contradicts no theorem but rules the scheme out wherever
signing happens under load. In a threshold deployment that gap is concrete: unauthorized
signatures on attacker-chosen messages, once enough sessions have run concurrently. No
public exploit against a deployed implementation has surfaced, but it is worth keeping in mind whenever signing protocols are chosen or composed.

**How to avoid.** Two complementary approaches.

_Structural._ Bind each challenge to the session's specific nonce commitment and
message so the adversary cannot freely choose challenges after observing the nonces.
FROST achieves this with a per-participant binding factor, standardized in
[RFC 9591](https://datatracker.ietf.org/doc/html/rfc9591). MuSig2
([Nick et al., CRYPTO 2021](https://eprint.iacr.org/2020/1261)) uses two aggregated
nonces per session whose specific linear combination is provably secure under
concurrent execution.

_Application-layer serialization._ These schemes are proven secure sequentially, so if the
protocol itself cannot be changed, simply run it that way: have the signer complete or abort
one session before starting the next. Full serialization is the safe rule, since the
polynomial attack needs about $\ell = 256$ open sessions while the sub-exponential variant
succeeds with fewer, so capping concurrency at a small bound is not enough.
