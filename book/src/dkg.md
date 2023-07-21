# Publicly Verifiable Distributed Key Generation

Ferveo uses a Publicly Verifiable Distributed Key Generator

The **Aggregatable DKG** scheme of Kobi Gurkan, Philipp Jovanovic, Mary Maller, Sarah Meiklejohn, Gilad Stern, and Alin Tomescu uses a similar approach to obtain an \\( O(n \log n)\\) time *asynchronous* DKG.

The primary advantage of a Publicly Verifiable DKG is that no complaint or dispute round is necessary; every validator can check that the DKG succeeded correctly, even for validators that remain offline during the entire DKG. 

The primary disadvantage of a Publicly Verifiable DKG is that most schemes produce a private key shares consisting of **group elements** instead of scalar field elements, and thus are incompatible with many existing cryptographic primitives.  Ferveo works around this issue by using novel cryptographic primitives, still based on standard cryptographic assumptions, that are compatible with the private key shares generated

Some Publicly Verifiable DKG schemes, such as Groth21, produce field private key shares. Such a scheme may be evaluated for use in Ferveo at a later date.
