libkop
======

KOP stands for (*K*EM-based *O*T)-based *P*EC,
which uses the following acronyms:
- KEM: Key Encapsulation Mechanism
- OT: Oblivious Transfer
- PEC: Private Equality Confirmation

The KOP allows secure comparison of low-entropy values, which can be used (for
example) in Off-the-Record Messaging (OTR) for user authentication. In OTR
version 2/3/4, this is done with the Socialist Millionaire Protocol.  That
protocol is based on the Diffie-Hellman key-exchange, which is not secure
against quantum adversaries.

Instead the KOP protocol can (in principle) be instantiated with any KEM,
including the post-quantum secure ones currently being developed. The current
prototype uses [Kyber][kyber], as provided by [liboqs][oqs]. The protocol must
be executed over a [pseudo-authenticated channel][bclpr07], which is
instantiated with [Dilithium][dilithium] signatures.

This work accompanies my thesis and relies on the work done by Masny,
Rindal and Rosulek [rr17], [mr19].


Compiling
---------

In order to compile the library, make sure that the following libraries are installed:
 - [libXKCP][https://github.com/XKCP/XKCP] (make sure the KeccakHash service is enabled)
 - [libdecaf][https://sourceforge.net/projects/ed448goldilocks/]
 - [liboqs][https://openquantumsafe.org/liboqs/]


Testing
-------

Once compiled, build the `all` target to build all test-files.
Run each `test_*` target to test the corresponding functionality.
(`test_kop` tests the overall functionality).
Run `test_speed` for benchmarking the code.


References
----------

- Peter Rindal and Mike Rosulek, 2017.
  Malicious-Secure Private Set Intersection via Dual Execution.
	[ePrint][rr17]
- Daniel Masny and Peter Rindal, 2019.
  Endemic Oblivious Transfer.
	[ePrint][mr19]
- Boaz Barak, Ran Canetti, Yehuda Lindell, Rafael Pass, and Tal Rabin, 2007.
  Secure Computation Without Authentication.
  [ePrint][bclpr07]
- Douglas Stebila, Michele Mosca.
  Post-quantum key exchange for the Internet and the Open Quantum Safe project.
	In Roberto Avanzi, Howard Heys, editors, Selected Areas in Cryptography (SAC) 2016, LNCS, vol. 10532, pp. 1–24. Springer, October 2017.
	[oqs]
- Cryptographic Suite for Algebraic Lattices (CRYSTALS).
  [Kyber][kyber], [Dilithium][dilithium]

[rr17]: https://eprint.iacr.org/2017/769
[mr19]: https://eprint.iacr.org/2019/706
[bclpr07]: https://eprint.iacr.org/2007/464
[oqs]: https://openquantumsafe.org
[kyber]: https://pq-crystals.org/kyber/
[dilithium]: https://pq-crystals.org/dilithium/
