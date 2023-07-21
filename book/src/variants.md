# Threshold Decryption (Variants)

Threshold decryption can be performed using one of two optional cryptographic strategies a.k.a *variants*:
- Simple
- Precomputed

The chosen variant dictates the decryption shares returned by nodes and how those shares are combined. Either variant can be used 
for decryption, and each has its advantages and disadvantages.


## Simple

When decrypting using the *Simple* variant, any arbitrary m-of-n set of nodes (where `m` is the threshold) will each return a *simple* decryption share, and *any*
`m` set of decryption shares can be combined to successfully decrypt the encrypted data. Any arbitrary combination of the `m` *simple* decryption shares from the `n` nodes
can be used to obtain the decrypted data.

This is the case where you can concurrently contact `n` nodes and simply wait until any `m` nodes respond with decryption shares.

### Advantages
- Any (arbitrary) `m` decryption shares out of `n` can be requested, obtained, and combined
- Any singular unresponsive node does not prevent the ability to combine returned *simple* decryption shares
- Only one request round is needed if done concurrently i.e. send `n` request, and wait for `m` replies. A total of
  `n - m + 1` nodes would have to not respond for the failure case.

### Disadvantages
- Since the `m` nodes are arbitrary, combining the decryption shares requires the requester to do a more computationally intensive operation.


## Precomputed

When decrypting using the *Precomputed* variant, you will first choose a specific sub-set of `m` nodes from `n` i.e pick an arbitrary `m-of-n` set of nodes (where `m` is the threshold),
and those specific `m` nodes need to reply with precomputed decryption shares. If any of those specific `m` nodes does not respond, you will need fail over logic. This could entail:
- using the *precomputed* variant again and choosing another group of `m` nodes, without any node(s) that didn't respond
- switching to *simple* variant if the first round of *precomputed* fails
- other combination of logic

### Advantages
In the happy path:
- faster operation since the requester only contacts `m` nodes so there is no need for the other `n - m`
- since the list of `m` nodes is known, the operation to combine the `m` *precomputed* decryption shares is less computationally intensive than *simple*, which can work well for a lightweight requester


### Disadvantages
- Underlying availability issue since if any of the specific `m` nodes is unresponsive it can cause the *precomputed* variant to fail
- If the happy path does not happen, failover logic is required and it can end up being an overall slower operation than the *simple* variant
