# CTG

CTG (Cryptography) is a module in semester 1.2 of the CSF course in Ngee Ann Polytechnic, where cryptographic concepts and algorithms are taught.

This repository contains Python code written as part of the module's assignment.

This program is the implementation of a cryptographic system that aims to fulfill PAIN (Privacy, Authentication, Integrity, and Non-repudiation)

This cryptographic system includes the implementation of:
1. Symmetric encryption (International Data Encryption Algorithm (IDEA))
2. Asymmetric encryption (El-Gamal)
3. Hashing (Whirlpool)


Flow:
=== Sender's Side ===
1. Sender inputs message and secret key (128-bit/16-character) for IDEA

(Creating Digital Signature)
2. Plaintext message is hashed using Whirlpool to form a Message Digest
3. Message Digest is encrypted with the Sender's private key using El-Gamal to form a Digital Signature

(Encrypting Message)
4. Plaintext message is encrypted with the user's secret key using IDEA

(Encrypting IDEA Secret Key)
5. Plaintext secret key is encrypted with the Receiver's public key using El-Gamal

(Delivery)
6. The Digital Signature, encrypted message and encrypted secret key is sent to the receiver

=== Receiver's Side ===
(Recovering Plaintext IDEA Secret Key)
1. Encrypted secret key is decrypted with the Receiver's private key using El-Gamal

(Recovering Plaintext Message)
2. Encrypted message is decrypted with the plaintext secret key using IDEA

(Recovering Message Hash)
3. Digital Signature is decrypted with the Sender's public key

(Verifying Message Integrity)
4. Hash plaintext message using Whirlpool
5. Compare obtained message hash with calculated message hash
6. Both hashes match --> Message has not been altered


*El-Gamal key pairs for sender and receiver are generated in the program