---
title: "Sequentially Secure Protocol used Concurrently"
class: "Protocol"
order: 4
---

**Examples:**

- Blind schnorr signatures and ROS.
- Concurrent SPDZ MAC check without appropriate synchronization. To be secure in the presence of multi-threading, the whole MAC check subprotocol needs to be treated as critical section, including the possible abort.

Note that the term "concurrent" is overloaded: It can refer to concurrency in a distributed system (standard in the MPC literature, including UC), or concurrency in the sense of multi-threading/cooperative multi-tasking etc (not covered by standard security models). A multi-threaded MPC implementation might need concurrent security in both meanings of the word.
