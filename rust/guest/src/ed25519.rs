//! `ed25519-verify` / `ed25519-sign` key creation.

use crate::{bindings, Error, SigningKey, SigningKeyOptions, UnwrapInput, VerifyingKey};

/// Import a 32-byte raw public key (RFC 8032 encoding). Material of any
/// other length fails [`Error::InvalidKey`]; a non-canonical or
/// small-order encoding is rejected here or at verification, per the WIT
/// interface's verification criterion.
pub async fn import_verifying_key_raw(raw: impl Into<Vec<u8>>) -> Result<VerifyingKey, Error> {
    Ok(VerifyingKey::from_raw(
        bindings::ed25519_verify::import_verifying_key_raw(raw.into()).await?,
    ))
}

/// Import a public key as an X.509 SubjectPublicKeyInfo (DER, RFC 8410).
/// The embedded point is subject to the same strict criterion as
/// [`import_verifying_key_raw`].
pub async fn import_verifying_key_spki(spki: impl Into<Vec<u8>>) -> Result<VerifyingKey, Error> {
    Ok(VerifyingKey::from_raw(
        bindings::ed25519_verify::import_verifying_key_spki(spki.into()).await?,
    ))
}

/// Import a public key as an RFC 8037 OKP public JWK (`kty: "OKP"`,
/// `crv: "Ed25519"`, `x`; as JSON text). An `alg` member, when present,
/// must be `"Ed25519"` or `"EdDSA"`. The same strict point criterion as
/// [`import_verifying_key_raw`] applies; see the WIT
/// `mac-key.export-key-jwk` doc for the package-wide JWK contract.
pub async fn import_verifying_key_jwk(jwk: impl Into<String>) -> Result<VerifyingKey, Error> {
    Ok(VerifyingKey::from_raw(
        bindings::ed25519_verify::import_verifying_key_jwk(jwk.into()).await?,
    ))
}

/// Generate a fresh random signing key, returning both halves.
pub async fn generate_key(options: SigningKeyOptions) -> Result<(SigningKey, VerifyingKey), Error> {
    let (signing, verifying) = bindings::ed25519_sign::generate_key(options.lower()).await?;
    Ok((
        SigningKey::from_raw(signing),
        VerifyingKey::from_raw(verifying),
    ))
}

/// Import a signing key as a PKCS#8 PrivateKeyInfo (DER, RFC 8410: the
/// 32-byte seed in a CurvePrivateKey). Returns only the signing key; the
/// public half is imported separately (there is no derive from a private
/// import — see the WIT `ed25519-sign` interface doc).
pub async fn import_signing_key_pkcs8(
    pkcs8: impl Into<Vec<u8>>,
    options: SigningKeyOptions,
) -> Result<SigningKey, Error> {
    Ok(SigningKey::from_raw(
        bindings::ed25519_sign::import_signing_key_pkcs8(pkcs8.into(), options.lower()).await?,
    ))
}

/// Import a signing key as an RFC 8037 OKP private JWK (`kty: "OKP"`,
/// `crv: "Ed25519"`, with `x` and `d` both required; as JSON text). An
/// `alg` member, when present, must be `"Ed25519"` or `"EdDSA"`.
///
/// Security: implementations MAY reject a JWK whose `x` is not the
/// public key of `d`, and never trust `x` for any operation.
pub async fn import_signing_key_jwk(
    jwk: impl Into<String>,
    options: SigningKeyOptions,
) -> Result<SigningKey, Error> {
    Ok(SigningKey::from_raw(
        bindings::ed25519_sign::import_signing_key_jwk(jwk.into(), options.lower()).await?,
    ))
}

/// Mint a signing key from unwrapped key material read as a PKCS#8
/// PrivateKeyInfo, subject to [`import_signing_key_pkcs8`]'s contract.
/// Consumes the [`UnwrapInput`]; the minted key's usages and
/// extractability come from `options` alone.
pub async fn unwrap_signing_key_pkcs8(
    input: UnwrapInput,
    options: SigningKeyOptions,
) -> Result<SigningKey, Error> {
    Ok(SigningKey::from_raw(
        bindings::ed25519_sign::unwrap_signing_key_pkcs8(input.into_raw(), options.lower()).await?,
    ))
}

/// Mint a signing key from unwrapped key material read as an OKP private
/// JWK, subject to [`import_signing_key_jwk`]'s contract plus the
/// unwrap-path `use`/`key_ops` checks (see the WIT `README.md`, "JWK
/// contract"). Consumes the [`UnwrapInput`]; see
/// [`unwrap_signing_key_pkcs8`] for the options model.
pub async fn unwrap_signing_key_jwk(
    input: UnwrapInput,
    options: SigningKeyOptions,
) -> Result<SigningKey, Error> {
    Ok(SigningKey::from_raw(
        bindings::ed25519_sign::unwrap_signing_key_jwk(input.into_raw(), options.lower()).await?,
    ))
}
