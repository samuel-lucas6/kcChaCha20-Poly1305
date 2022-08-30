[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/cChaCha20-Poly1305/blob/main/LICENSE)

# cChaCha20-Poly1305

A key-committing implementation of [ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439).

This technique is an encryption version of the padding fix discussed in [*How to Abuse and Fix Authenticated Encryption Without Key Commitment*](https://eprint.iacr.org/2020/1456.pdf). Credit goes to Loup Vaillant for the [idea](https://www.reddit.com/r/crypto/comments/opm10n/do_i_need_a_key_committing_aead_to_be_random_key/).

The latter 32 bytes of block 0 (after the Poly1305 key) are prepended to the ciphertext as a commitment. For decryption, this commitment is checked in constant time alongside the tag, eliminating a timing difference.

This provides 128-bit key-committing security but incurs additional storage overhead. If combined with the [Hash-then-Encrypt](https://eprint.iacr.org/2022/268.pdf) strategy (`subkey = KDF(masterKey, nonce || associatedData`), this *should* commit to all inputs.
