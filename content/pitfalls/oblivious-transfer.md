---
title: "Oblivious Transfer"
class: "Cryptographic Primitive"
order: 15
---

- Many oblivious transfer extension protocols rely on consistency checks to get active security. However, they suffer from selective abort attacks, where succeeding or failing a consistency check leaks a few bits of information on the underlying OT secret. As a result, reusing the base OT secrets for multiple OT extension protocols is dangerous.
    - [DKLs23](https://eprint.iacr.org/2023/765.pdf) states that an abort during OT extension requires the involved party to abort all instances of the protocol running in parallel that involve the offending party. This is extremely difficult to guarantee from an engineering standpoint.
