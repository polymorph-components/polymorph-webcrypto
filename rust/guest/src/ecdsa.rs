//! `ecdsa-verify` / `ecdsa-sign` key creation.

use crate::{bindings, Error, SigningKey, SigningKeyOptions, UnwrapInput, VerifyingKey};

pub use crate::bindings::ecdsa_verify::EcdsaVariant;

/// Import a public key as an uncompressed SEC1 point.
pub async fn import_verifying_key_raw(
    variant: EcdsaVariant,
    raw: impl Into<Vec<u8>>,
) -> Result<VerifyingKey, Error> {
    Ok(VerifyingKey::from_raw(
        bindings::ecdsa_verify::import_verifying_key_raw(variant, raw.into()).await?,
    ))
}

/// Import a public key as an X.509 SubjectPublicKeyInfo (DER). The curve
/// must be named by OID and match the declared variant's, or the import
/// fails [`Error::InvalidKey`]; whether a *compressed* point encoding is
/// accepted is implementation-defined — do not rely on either behavior
/// (see the WIT `import-verifying-key-spki` doc).
pub async fn import_verifying_key_spki(
    variant: EcdsaVariant,
    spki: impl Into<Vec<u8>>,
) -> Result<VerifyingKey, Error> {
    Ok(VerifyingKey::from_raw(
        bindings::ecdsa_verify::import_verifying_key_spki(variant, spki.into()).await?,
    ))
}

/// Import a public key as an EC public JWK (`kty: "EC"`, with `crv`,
/// `x`, and `y`; as JSON text). The JWK's `crv` must match the declared
/// variant's curve, and an `alg` member, when present, must be the
/// curve's JOSE signature alg (`"ES256"` for P-256, `"ES384"` for
/// P-384). See the WIT `mac-key.export-key-jwk` doc for the package-wide
/// JWK contract.
pub async fn import_verifying_key_jwk(
    variant: EcdsaVariant,
    jwk: impl Into<String>,
) -> Result<VerifyingKey, Error> {
    Ok(VerifyingKey::from_raw(
        bindings::ecdsa_verify::import_verifying_key_jwk(variant, jwk.into()).await?,
    ))
}

/// Generate a fresh random signing key of the declared variant, returning
/// both halves.
pub async fn generate_key(
    variant: EcdsaVariant,
    options: SigningKeyOptions,
) -> Result<(SigningKey, VerifyingKey), Error> {
    let (signing, verifying) = bindings::ecdsa_sign::generate_key(variant, options.lower()).await?;
    Ok((
        SigningKey::from_raw(signing),
        VerifyingKey::from_raw(verifying),
    ))
}

/// Import a signing key as a PKCS#8 PrivateKeyInfo (DER, the SEC1
/// private-key body). The encoded curve must match the declared
/// variant's ([`Error::InvalidKey`]); an embedded public key, when
/// present, is validated against the scalar and never trusted on its
/// own. Returns only the signing key; the public half is imported
/// separately (there is no derive from a private import — see the WIT
/// `ecdsa-sign` interface doc).
pub async fn import_signing_key_pkcs8(
    variant: EcdsaVariant,
    pkcs8: impl Into<Vec<u8>>,
    options: SigningKeyOptions,
) -> Result<SigningKey, Error> {
    Ok(SigningKey::from_raw(
        bindings::ecdsa_sign::import_signing_key_pkcs8(variant, pkcs8.into(), options.lower())
            .await?,
    ))
}

/// Import a signing key as an EC private JWK (`kty: "EC"`, with `crv`,
/// `d`, and the mandatory public coordinates `x`/`y`; as JSON text).
/// `crv` and `alg` are validated as in [`import_verifying_key_jwk`].
///
/// Security: implementations MAY validate `x`/`y` against `d`, and never
/// trust them for any operation.
pub async fn import_signing_key_jwk(
    variant: EcdsaVariant,
    jwk: impl Into<String>,
    options: SigningKeyOptions,
) -> Result<SigningKey, Error> {
    Ok(SigningKey::from_raw(
        bindings::ecdsa_sign::import_signing_key_jwk(variant, jwk.into(), options.lower()).await?,
    ))
}

/// Mint a signing key from unwrapped key material read as a PKCS#8
/// PrivateKeyInfo, subject to [`import_signing_key_pkcs8`]'s contract.
/// Consumes the [`UnwrapInput`]; the minted key's usages and
/// extractability come from `options` alone.
pub async fn unwrap_signing_key_pkcs8(
    variant: EcdsaVariant,
    input: UnwrapInput,
    options: SigningKeyOptions,
) -> Result<SigningKey, Error> {
    Ok(SigningKey::from_raw(
        bindings::ecdsa_sign::unwrap_signing_key_pkcs8(variant, input.into_raw(), options.lower())
            .await?,
    ))
}

/// Mint a signing key from unwrapped key material read as an EC private
/// JWK, subject to [`import_signing_key_jwk`]'s contract plus the
/// unwrap-path `use`/`key_ops` checks (see the WIT `README.md`, "JWK
/// contract"). Consumes the [`UnwrapInput`]; see
/// [`unwrap_signing_key_pkcs8`] for the options model.
pub async fn unwrap_signing_key_jwk(
    variant: EcdsaVariant,
    input: UnwrapInput,
    options: SigningKeyOptions,
) -> Result<SigningKey, Error> {
    Ok(SigningKey::from_raw(
        bindings::ecdsa_sign::unwrap_signing_key_jwk(variant, input.into_raw(), options.lower())
            .await?,
    ))
}
