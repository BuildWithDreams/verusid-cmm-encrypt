//! Raw Sapling recipient encryption using the Verus VDXF AEAD construction.

use jubjub::{AffinePoint, ExtendedPoint};
use rand_core::{CryptoRng, RngCore};

use crate::api::EncryptError;
use crate::crypto::{aead_encrypt, kdf_sapling, sapling_ka_agree};
use crate::ephemeral::{derive_epk, derive_g_d, generate_esk};

/// Maximum raw recipient plaintext size, in bytes.
pub const MAX_RECIPIENT_PLAINTEXT_BYTES: usize = 16_368;

/// Raw AEAD output for a Sapling recipient.
#[derive(Debug)]
pub struct RecipientCiphertext {
    /// Compressed ephemeral Jubjub public key.
    pub epk: [u8; 32],
    /// Encrypted plaintext with the 16-byte Poly1305 tag appended.
    pub ciphertext: Vec<u8>,
    /// Symmetric key specific to this encryption.
    pub ssk: [u8; 32],
}

/// Errors from recipient validation and raw recipient encryption.
#[derive(Debug, PartialEq, Eq)]
pub enum RecipientEncryptError {
    /// The diversifier or diversified transmission key is invalid.
    InvalidRecipient,
    /// The plaintext exceeds the raw recipient limit.
    InvalidInput,
    /// The encryption could not derive a usable ephemeral key or ciphertext.
    EncryptFailed,
}

/// Check for a canonical, non-identity, prime-order Jubjub public key.
pub fn is_valid_recipient_epk(pk_d: &[u8]) -> bool {
    let Ok(bytes) = <[u8; 32]>::try_from(pk_d) else {
        return false;
    };
    let Some(point) = Option::<AffinePoint>::from(AffinePoint::from_bytes(bytes)) else {
        return false;
    };
    let extended = ExtendedPoint::from(point);
    point.to_bytes() == bytes
        && extended != ExtendedPoint::identity()
        && bool::from(extended.is_torsion_free())
}

/// Validate the Sapling diversifier and diversified transmission key.
pub fn validate_recipient(d: &[u8], pk_d: &[u8]) -> Result<(), RecipientEncryptError> {
    checked_recipient(d, pk_d).map(|_| ())
}

/// Encrypt raw bytes to a Sapling recipient with a freshly sampled nonzero ESK.
///
/// The supplied RNG must be cryptographically secure. The plaintext limit is
/// [`MAX_RECIPIENT_PLAINTEXT_BYTES`].
pub fn encrypt_for_recipient<R: RngCore + CryptoRng>(
    plaintext: &[u8],
    d: &[u8],
    pk_d: &[u8],
    rng: &mut R,
) -> Result<RecipientCiphertext, RecipientEncryptError> {
    if plaintext.len() > MAX_RECIPIENT_PLAINTEXT_BYTES {
        return Err(RecipientEncryptError::InvalidInput);
    }
    let (d, pk_d) = checked_recipient(d, pk_d)?;
    for _ in 0..64 {
        let esk = generate_esk(rng);
        if esk != [0; 32] {
            return encrypt_with_esk(plaintext, d, pk_d, &esk)
                .map_err(|_| RecipientEncryptError::EncryptFailed);
        }
    }
    Err(RecipientEncryptError::EncryptFailed)
}

fn checked_recipient<'a>(
    d: &'a [u8],
    pk_d: &'a [u8],
) -> Result<(&'a [u8; 11], &'a [u8; 32]), RecipientEncryptError> {
    let invalid = |_| RecipientEncryptError::InvalidRecipient;
    let d = <&[u8; 11]>::try_from(d).map_err(invalid)?;
    let pk_d = <&[u8; 32]>::try_from(pk_d).map_err(invalid)?;
    if !is_valid_recipient_epk(pk_d) || derive_g_d(d).is_none() {
        return Err(RecipientEncryptError::InvalidRecipient);
    }
    Ok((d, pk_d))
}

// Preserve the envelope's original RNG draw and support for arbitrary sizes.
pub(crate) fn encrypt_envelope_pass1<R: RngCore + CryptoRng>(
    plaintext: &[u8],
    d: &[u8; 11],
    pk_d: &[u8; 32],
    rng: &mut R,
) -> Result<RecipientCiphertext, EncryptError> {
    encrypt_with_esk(plaintext, d, pk_d, &generate_esk(rng))
}

fn encrypt_with_esk(
    plaintext: &[u8],
    d: &[u8; 11],
    pk_d: &[u8; 32],
    esk: &[u8; 32],
) -> Result<RecipientCiphertext, EncryptError> {
    let epk = derive_epk(esk, d)?;
    let dhsecret = sapling_ka_agree(esk, pk_d)?;
    let ssk = kdf_sapling(&dhsecret, &epk);
    let ciphertext = aead_encrypt(&ssk, plaintext);
    Ok(RecipientCiphertext {
        epk,
        ciphertext,
        ssk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    // Sapling key-components vector row 2 (VerusCoin src/test/data/sapling_key_components.json):
    // diversifier in written order, pk_d reversed once for Verus uint256 storage order.
    // The (d, pk_d) pair below is the pair the pinned v1.2.18 daemon accepted for encryption
    // and whose ciphertext it decrypted back to the sent payload.
    const D_HEX: &str = "f19d9b797e39f337445839";
    // BYTE ORDER, measured against v1.2.18 rather than assumed: the daemon's address carries
    // the pk_d bytes it will encrypt to, and those are exactly the bytes this crate consumes —
    // no reversal at the AEAD boundary. Verus presents the same material in `uint256::SetHex`
    // order elsewhere, so the *canonical* vector column is the reverse of the bytes in the
    // address, and `decryptdata`'s `ivk` argument must be given reversed. Both directions were
    // confirmed live: this tuple encrypted to a `flags:5` leaf and that leaf decrypted back
    // with the reversed IVK.
    const PK_D_HEX: &str = "db4cd2b0aac4f7eb8ca131f16567c445a9555126d3c29f14e3d776e841ae7415";
    // A small, definitely-valid Jubjub scalar: 1 in canonical little-endian form.
    const ESK_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000";

    fn hex32(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0, "hex must be whole bytes");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex"))
            .collect()
    }

    fn recipient() -> (Vec<u8>, Vec<u8>) {
        let d = hex32(D_HEX);
        let pk_d = hex32(PK_D_HEX);
        assert_eq!(d.len(), 11, "diversifier is 11 bytes");
        assert_eq!(pk_d.len(), 32, "pk_d is 32 bytes");
        (d, pk_d)
    }

    #[test]
    fn chosen_esk_is_deterministic_and_matches_the_envelope_construction() {
        let (d, pk_d) = recipient();
        let esk = hex32(ESK_HEX);
        let esk: [u8; 32] = esk.as_slice().try_into().expect("32-byte esk");
        let (d, pk_d): ([u8; 11], [u8; 32]) = (
            d.as_slice().try_into().expect("11-byte d"),
            pk_d.as_slice().try_into().expect("32-byte pk_d"),
        );
        let a = encrypt_with_esk(b"chosen-esk probe", &d, &pk_d, &esk).expect("chosen esk encrypts");
        let b = encrypt_with_esk(b"chosen-esk probe", &d, &pk_d, &esk).expect("chosen esk is repeatable");
        assert_eq!(a.epk, b.epk, "same esk must yield the same epk");
        assert_eq!(a.ciphertext, b.ciphertext, "same esk must yield the same ciphertext");
        assert_eq!(a.ssk, b.ssk, "same esk must yield the same symmetric key");
        assert_eq!(a.ciphertext.len(), b"chosen-esk probe".len() + 16, "Poly1305 tag is appended");

        // The raw seam must be the same construction the envelope path uses: give both paths
        // the identical derived scalar, since `generate_esk` reduces RNG output to a scalar.
        let derived = generate_esk(&mut FakeRng(esk));
        let env = encrypt_envelope_pass1(b"chosen-esk probe", &d, &pk_d, &mut FakeRng(esk))
            .expect("envelope pass1 encrypts");
        let raw = encrypt_with_esk(b"chosen-esk probe", &d, &pk_d, &derived)
            .expect("raw seam encrypts with the derived scalar");
        assert_eq!(raw.epk, env.epk, "raw and envelope paths must derive the same epk");
        assert_eq!(raw.ciphertext, env.ciphertext, "raw and envelope paths must produce the same bytes");
    }

    #[test]
    fn distinct_esk_yields_distinct_epk_and_ciphertext() {
        let (d, pk_d) = recipient();
        let mut rng = OsRng;
        let one = encrypt_for_recipient(b"same plaintext", &d, &pk_d, &mut rng).expect("first seal");
        let two = encrypt_for_recipient(b"same plaintext", &d, &pk_d, &mut rng).expect("second seal");
        assert_ne!(one.epk, two.epk, "fresh esk must change epk");
        assert_ne!(one.ciphertext, two.ciphertext);
    }

    #[test]
    fn plaintext_cap_is_inclusive_at_16_368_and_rejects_16_369() {
        let (d, pk_d) = recipient();
        let mut rng = OsRng;
        let at_cap = vec![0x5a; MAX_RECIPIENT_PLAINTEXT_BYTES];
        let sealed = encrypt_for_recipient(&at_cap, &d, &pk_d, &mut rng).expect("cap is inclusive");
        assert_eq!(sealed.ciphertext.len(), MAX_RECIPIENT_PLAINTEXT_BYTES + 16);

        let over_cap = vec![0x5a; MAX_RECIPIENT_PLAINTEXT_BYTES + 1];
        assert_eq!(
            encrypt_for_recipient(&over_cap, &d, &pk_d, &mut rng).err(),
            Some(RecipientEncryptError::InvalidInput)
        );
    }

    #[test]
    fn validator_rejects_malformed_recipients() {
        let (d, pk_d) = recipient();
        assert!(validate_recipient(&d, &pk_d).is_ok(), "the daemon-accepted tuple must validate");
        assert_eq!(validate_recipient(&d[..10], &pk_d), Err(RecipientEncryptError::InvalidRecipient));
        assert_eq!(validate_recipient(&d, &pk_d[..31]), Err(RecipientEncryptError::InvalidRecipient));

        // Identity is neither canonical-prime-order nor a usable transmission key.
        assert!(!is_valid_recipient_epk(&[0u8; 32]));
        assert_eq!(validate_recipient(&d, &[0u8; 32]), Err(RecipientEncryptError::InvalidRecipient));

        // Ciphertext length is enforced by the AEAD path, and a truncated diversifier is
        // rejected before any encryption work (covered above). No assumption is made about
        // which arbitrary diversifier bytes happen to lack a valid g_d.
    }

    /// Deterministic RNG used only to reach the envelope path with a fixed esk.
    struct FakeRng([u8; 32]);

    impl RngCore for FakeRng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for (i, byte) in dest.iter_mut().enumerate() {
                *byte = self.0[i % 32];
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for FakeRng {}
}
