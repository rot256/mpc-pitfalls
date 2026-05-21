---
title: "Blockdaemon Builder Vault warns against 2-of-3 presignature reuse"
category: concurrency-and-state-handling
subcategory: "Threshold Presignature Reuse (Nonce Reuse)"
date: 2024-01-01
primitives: [signature]
source:
  - name: "Builder Vault TSM docs"
    url: https://builder-vault-tsm.docs.blockdaemon.com/docs/presignatures
hidden: false
---

Builder Vault is Blockdaemon's production MPC threshold-signing platform (powered by
the Sepior TSM). Its developer documentation explains that each presignature contains
shares of a random signing nonce, and that an MPC node enforces single-use by
deleting the presignature in the same transaction in which it consumes its share.
The docs additionally warn that backup-and-restore can reintroduce a
previously-consumed presignature, turning a routine ops procedure into a
key-extraction vector if mishandled. Operators are therefore instructed to delete
all presignatures either before taking a database backup or upon restoring.
