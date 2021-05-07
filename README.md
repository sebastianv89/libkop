libkop
======

KOP stands for (*K*EM-based *O*T)-based *P*ET,
which uses the following acronyms:
- KEM: Key Encapsulation Mechanism
- OT: Oblivious Transfer
- PET: Private Equality Test

The KOP allows secure comparison of low-entropy values, which can be used (for
example) in Off-the-Record messaging (OTR) for user authentication. In OTR
version 2/3/4, this is done with the Socialist Millionaire Protocol.  That
protocol is based on the Diffie-Hellman key-exchange, which is not secure
against quantum adversaries.

Instead the KOP protocol can (in principle) be instantiated with any KEM,
including the post-quantum secure ones currently being developed. The current
prototype uses [Kyber][kyber], as provided by [liboqs][oqs].

This work accompanies my upcoming paper and relies on the work done by Masny,
Rindal and Rosulek [rr17], [mr19].

References
----------

- Peter Rindal and Mike Rosulek, 2017.
  Malicious-Secure Private Set Intersection via Dual Execution.
	[ePrint][rr17]
- Daniel Masny and Peter Rindal, 2019.
  Endemic Oblivious Transfer.
	[ePrint][mr19]
- Douglas Stebila, Michele Mosca.
  Post-quantum key exchange for the Internet and the Open Quantum Safe project.
	In Roberto Avanzi, Howard Heys, editors, Selected Areas in Cryptography (SAC) 2016, LNCS, vol. 10532, pp. 1–24. Springer, October 2017.
	[oqs]

[rr17]: https://eprint.iacr.org/2017/769
[mr19]: https://eprint.iacr.org/2019/706
[oqs]: https://openquantumsafe.org
[kyber]: https://pq-crystals.org/kyber/
