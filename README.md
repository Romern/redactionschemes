# Golang Library for Redactable Signatures

**⚠️WARNING⚠️ THIS LIBRARY HAS NOT BEEN VERIFIED AT ALL AND IS PROBABLY NOT SAFE TO USE!!!**

This library includes 3 verifiable redaction schemes:

- A naive scheme
- A Merkle tree-based scheme by [Johnson et al.](https://dl.acm.org/doi/10.5555/646140.680938)
- An RSA-based scheme by [Johnson et al.](https://dl.acm.org/doi/10.5555/646140.680938)

Currently, all schemes use SHA256 for hashing, and the Merkle and Naive scheme use ECDSA for signing.

For examples, look at the tests.

## Partitioning

To keep the signatures small and the sign/verify/redact operations efficient, the input data is stored in partitions of data.
We provide a helper struct ``PartitionedData`` with many helper functions to handle this.

## TODO

- Make hash function modular.
- Probably replace ``PartitionedData`` with something more sensible?
- Merkle tree-based scheme very convoluted logic

## Short Description of Each Scheme

### Naive Scheme

``NaiveSignature`` simply uses the underlying ECDSA key to sign each partition individually.
To prohibit the reuse of each partition (reordering attack), we append an ID on each hash, as well as its position. We hard coded the hash of the data as ID. For a message m of length n, the signature is:

```
Sig(H(n || ID)) || Sig(H(ID || 0 || m_0)) || ... || Sig(H(ID || n || m_n))

```

### Merkle Tree-based Scheme

``JohnsonMerkleSignature`` is based on [Johnson et al.](https://dl.acm.org/doi/10.5555/646140.680938) and uses a Merkle tree-based structure to sign the data.
The signature benefits from consecutive redactions, as neighboring redacted nodes in the Merkle tree will be merged. Thus the signature is largest, if the redaction is sparse.

### RSA-based Scheme

``JohnsonRSASignature`` is based on [Johnson et al.](https://dl.acm.org/doi/10.5555/646140.680938) and uses the RSA accumulator technique to achieve a constant sized signature. 
This currently use a hash function which maps to the primes, I don't know if this is safe or even sane...
Due to the repeated exponentiations, this scheme can get really slow!