#ifndef CSODIUM_SHIM_H
#define CSODIUM_SHIM_H

#include <stddef.h>

// libsodium 1.0.22 (Homebrew) — audited, statically linked per Phase 1 D-02.
// Only the symbols PKCryptEngine needs are declared here; the static archive is
// linked via /opt/homebrew/lib/libsodium.a in Package.swift. This is FFI
// marshaling only — no cryptography is re-implemented.
//
// Signatures match libsodium's published, stable API (sodium.h).

int sodium_init(void);

// crypto_sign_ed25519_pk_to_curve25519: convert a 32-byte Ed25519 public key to
// a 32-byte X25519 public key. Returns 0 on success. This is the one primitive
// CryptoKit cannot provide (Phase-1 locked).
int crypto_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
                                         const unsigned char *ed25519_pk);

// crypto_aead_xchacha20poly1305_ietf_decrypt: XChaCha20-Poly1305 (IETF) AEAD
// decrypt with a 24-byte nonce — the only correct provider for PKCrypt cipher
// 0x01 (CryptoKit ChaChaPoly is 12-byte-nonce and NOT interchangeable). The
// ciphertext MUST be the combined `ct || tag` buffer (16-byte tag). nsec is
// unused (pass NULL). Returns 0 on success, -1 on auth/tamper failure. This is
// the single primitive CryptoKit cannot provide for the XChaCha read path.
int crypto_aead_xchacha20poly1305_ietf_decrypt(
    unsigned char *m, unsigned long long *mlen_p,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub, const unsigned char *k);

#endif /* CSODIUM_SHIM_H */
