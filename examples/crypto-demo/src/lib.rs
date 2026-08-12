//! `crypto-demo`: an example WebAssembly component that exercises the
//! `polymorph:webcrypto` primitive kinds end to end through the
//! `polymorph-webcrypto-guest` library.
//!
//! The component is host-agnostic: the same binary runs unchanged under the
//! Wasmtime (RustCrypto) host and the jco (browser WebCrypto) host, which is
//! what demonstrates cross-implementation compatibility. Each kind gets one
//! happy-path tour (against a known-answer vector where the algorithm has a
//! deterministic one); the remaining checks assert the library's wrapper
//! plumbing — the lazy `Seal` future, every `DataSource` variant, the
//! `Error::Read` precedence rule — which executes nowhere else in the
//! repository. Algorithm correctness and the rejection surface are the
//! conformance suites' job (`conformance/`), which gate the same targets.
//! The `check(...)` names below are the inventory, and the integration
//! tests assert the expected summary.
//!
//! The `rsa-oaep` cargo feature (default on) adds the key-transport
//! check. The fully in-guest composition runs the `--no-default-features`
//! build instead: a component's imports are derived from the calls it
//! makes, and the in-guest provider withholds every RSA op interface
//! (rust/guest-provider/README.md, class D), so the composable artifact
//! must never make those calls — with them, `wac plug` fails.

wit_bindgen::generate!({
    path: "wit",
    world: "crypto-demo",
    generate_all,
});

use anyhow::{ensure, Context, Result};
use data_encoding_macro::hexlower;
use exports::demo::webcrypto_demo::demo::Guest;
use polymorph_webcrypto_guest::aes_gcm::AesVariant;
use polymorph_webcrypto_guest::sha2::Sha2Variant;
use polymorph_webcrypto_guest::{wit_stream, Error};

/// Assert that `result` failed with an error matching `pattern` (e.g.
/// `Error::InvalidKey(_)`). `accepted` says what its wrongly succeeding
/// would mean.
macro_rules! expect_error {
    ($result:expr, $pattern:pat, $accepted:expr $(,)?) => {
        match $result {
            Err(err) if matches!(err, $pattern) => Ok(()),
            Err(other) => Err(anyhow::Error::new(other).context(concat!(
                "expected ",
                stringify!($pattern),
                ", got"
            ))),
            Ok(_) => anyhow::bail!($accepted),
        }
    };
}

// --- RFC 4231 test case 2 (HMAC-SHA-256) ------------------------------------

const HMAC_KEY: &[u8] = b"Jefe";
const HMAC_DATA: &[u8] = b"what do ya want for nothing?";
const HMAC_TAG: [u8; 32] =
    hexlower!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

// --- NIST GCM revised spec, test case 16 (AES-256-GCM) ----------------------

const GCM_KEY: [u8; 32] =
    hexlower!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
const GCM_IV: [u8; 12] = hexlower!("cafebabefacedbaddecaf888");
const GCM_PLAINTEXT: [u8; 60] = hexlower!(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
     1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
);
const GCM_AAD: [u8; 20] = hexlower!("feedfacedeadbeeffeedfacedeadbeefabaddad2");
const GCM_CIPHERTEXT: [u8; 60] = hexlower!(
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
     8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
);
const GCM_TAG: [u8; 16] = hexlower!("76fc6ece0f4e1768cddf8853bb2d551b");

// --- RFC 3394 §4.1 (AES-KW: a 128-bit KEK wrapping 128 bits of key data) -----

const KW_KEK: [u8; 16] = hexlower!("000102030405060708090a0b0c0d0e0f");
const KW_DATA: [u8; 16] = hexlower!("00112233445566778899aabbccddeeff");
const KW_WRAPPED: [u8; 24] = hexlower!("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");

// --- RFC 8032 §7.1 test 2 (Ed25519) ------------------------------------------

const ED25519_PUBLIC: [u8; 32] =
    hexlower!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
const ED25519_MESSAGE: &[u8] = &[0x72];
const ED25519_SIG: [u8; 64] = hexlower!(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
     085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
);

// --- RFC 6979 A.2.5 (ECDSA P-256 + SHA-256, message "sample") ----------------

const ECDSA_PUBLIC_X: [u8; 32] =
    hexlower!("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
const ECDSA_PUBLIC_Y: [u8; 32] =
    hexlower!("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");
const ECDSA_MESSAGE: &[u8] = b"sample";
const ECDSA_SIG_R: [u8; 32] =
    hexlower!("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");
const ECDSA_SIG_S: [u8; 32] =
    hexlower!("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");

// --- Wycheproof RSA-2048 + SHA-256: rsa_signature_2048_sha256_test.json
//     tcId 1 and rsa_pss_2048_sha256_mgf1_32_test.json tcId 1 (sLen 32).
//     Both files carry the same public key, and both tcId-1 messages are
//     empty. -------------------------------------------------------------

const RSA_SPKI: [u8; 294] = hexlower!(
    "30820122300d06092a864886f70d01010105000382010f003082010a02820101\
     00a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224\
     e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac88450\
     97b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c9\
     8e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9\
     814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece\
     6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a\
     1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1\
     a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9\
     d50203010001"
);
const RSA_MESSAGE: &[u8] = b"";
const RSA_PKCS1_SIG: [u8; 256] = hexlower!(
    "840f5dac53106dd1f9c57219224cf51289290c42f20466875ba8e830ac5690e5\
     41536fcc8ab03b731f82bf66d83f194e7e180b3963ec7a2f3f7904a7ce49aed4\
     7da4d4b79421eaf937d301b3e696169297b797c32c076a12be4de0b58e003c51\
     23051a84a10c62f8dac2f42a8640008eb3c7cccd6760ff5b51b6897639225828\
     45f048fb8150e5a7a6ca2eccc7bdc85349ad5b26c52137a79fa3fe5c29ab5cd7\
     615013219c1941b6708e9c3c23feff5febaf0c8ebca5750b54e3e6e99a3e876b\
     396f27860b7f3ec4e9191703c6332d944f6f69751167680c79c4f6b57f1cc875\
     5d24b6ec158ccdbacdb23107a33cb6b332516c13274d1f9dccc21dced869e486"
);
const RSA_PSS_SIG: [u8; 256] = hexlower!(
    "4f01e0c12b08625ecac89a69231906edf826380f37c959a96690d046316d68ff\
     ce9d5c471694fcebfc6b45534864689256e4fc81c78e583f675d0c94b4496474\
     51e81beff01a11a516d5e5ce3f1a910437cb8a3a5096b19fb15f4524a35b23d8\
     9cdba12cf5b71aac1047b28c562df7c5542c34ce23a182cf7e0e231934b17294\
     799d44877a1d68ef1b8f073619b7618e6b7c22db20030d98cf591ffc3d4da5f5\
     8613ecd5ecfc3b40a1d02f40891ca43695cd4c088b05a8054c89c595a47e2748\
     16f35384226f74459ee63e25a1bfc03c360490552ec38343f8ace502f065303b\
     00bc0ec320711b211fde92e57feb9013c3609342495ec0d7cabdec21e54acc38"
);

// --- Wycheproof rsa_oaep_2048_sha256_mgf1sha256_test.json: group 1's key
//     (the same 2048-bit modulus as RSA_SPKI above) as PKCS#8 and as the
//     file's full-CRT private JWK, a public JWK built from its n/e, and
//     tcId 2's known answer (twenty 0x00 bytes, empty label). Compiled only
//     with the `rsa-oaep` feature: the composable build must not touch
//     the interfaces the in-guest provider withholds. -------------------

#[cfg(feature = "rsa-oaep")]
const OAEP_PKCS8: [u8; 1217] = hexlower!(
    "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201\
     000282010100a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094f\
     a1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89\
     d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e\
     42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed\
     81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be\
     82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f11264\
     22f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c\
     4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf782\
     0283f742b9d502030100010282010024cdc62317f5d72a6f6ba6cc9632899b01\
     d1ff28867d72f61688995bc855a4e420a8405250089bdb13cf8e09543827b748\
     b9d27fbb2b4d9e20af8c5a6a862796d1a4cc18ad16ea678bc1bd4a83bbbe9c5e\
     57453b5ce7388e41a3ba4ce2b77b4438a229e954f720dae0353dc088ac8a76b2\
     6dc276f8e1b7851ddd6398ad16ff2e78195123b9b036e945c38c9d12434f6df7\
     6fe22359eb3e1ac9c011678fc926fad3ae475a4fffff55feb2d147e9c894f4c0\
     e29a599e762462482d968bf42780945fc0d2c31c573c4431b8f4fe8b8c67bec8\
     15abd44f7a86edca1c2308737358d2c2ae5e2e0e2dadf730980262377e58b13b\
     7d9992060a0bc870ccfdb4a9319ee102818100dc431050f782e894fb5248247d\
     98cb7d58b8d1e24f3b55d041c56e4de086b0d5bb028bda42eeb5d234d5681e58\
     09d415e6a289ad4cfbf78f978f6c35814f50eebff1c5b80a69f788e81e6bab5d\
     daa78369d659d143ec6f17e79813a575cfad9c569156b90113e2e9110ad9e7b4\
     8a1c9348a6e653321191290ea36cfb3a5b18f102818100bd1a81e7977f989812\
     2273ae3222b598ea5fb19eb4eabc38308a5e32196603b2e500ffb79f5b886816\
     611debc472fac45544070beb057c941378a6868af3b7a03d3f9880ec47d5e089\
     b94fbde542aba9ae8d72c57088d7abf5b131f39098f7bc160f90536abc9492fd\
     4e06f3ed7299d4b97bb03677207d95669f140cfbc20f2502818100a94b528b28\
     f291599121d91952ffd1c7f21d7c1479d99d478885fb161870ee1218bf084726\
     12dbe5497e8d9c650688e09c786961ae3e2c354dc48ae34514759c4c23c45884\
     88961dc06b414e61c0e1e7fbbd2923d31532fe289f96da220711e58c14019808\
     e00414276933bb07e4efb9b4a9b37656917205209f33f09515d7c10281803af0\
     e72a933aef09ff2503df78bafed531c02ff1a2bc437c540cdcbd4ad35435cf51\
     1763596543480629b114ca7f780ff7efa32ea0cb6e000d6d9ea1f2ef71fd9cf9\
     948422a165557e37e755edfe70d90b920502eb478bc98a63f788ce3a0f856d6e\
     de7251a383bfa8fa480a81a925af7b3cc538c4bab8c9f7597ffb68011d8d0281\
     802640fbfbcfefb163ee7a87b6483a66ee41f956d90fa8a7939bfc042ee0924b\
     1b7993d0445f758d51933e85179c0320b0c968b48a91c38b5be923e1097c0c56\
     2f88d42294b6a2759bafa5428a74f1270874e45f6fcc60f21602de5eccd143cf\
     31241f5921b5ad3983fb54ef17be3b285367e50c999c67247b552fe4bfce945f\
     7b"
);
#[cfg(feature = "rsa-oaep")]
const OAEP_PRIVATE_JWK: &str = r#"{"kty":"RSA","alg":"RSA-OAEP-256","n":"orRRoH0KpfluRVZxUTVQUUqKW0YuvvcXCU-h_ugiJOY3-XRtP3yv0xh42AMltu9aFwD2WQO0aUKeidbqyIRQl7WrOTGJ25JRLtincRoSU_rNIPecFegkfz0-QuRuSMmOJUov6XZTE6A-_48X4aApOXofomqNzib0kO2BKZYV2YFMItphBCjgnH2WWFlCZvXAIdD87KCNlFoSvoLeTR7Oa0wDFFtdNJXU7VQR64eNrwX9evw-Ca2g8RJkIvWQl1oZaYFvSGmLy7obTZyuedRg2Pn4Xnl1AF2bwixOWsD3waRdElaaYoB9O5oC5aUw53MGb0U9H1tMLpz3ggKD90K51Q","e":"AQAB","kid":"none","d":"JM3GIxf11ypva6bMljKJmwHR_yiGfXL2FoiZW8hVpOQgqEBSUAib2xPPjglUOCe3SLnSf7srTZ4gr4xaaoYnltGkzBitFupni8G9SoO7vpxeV0U7XOc4jkGjukzit3tEOKIp6VT3INrgNT3AiKyKdrJtwnb44beFHd1jmK0W_y54GVEjubA26UXDjJ0SQ09t92_iI1nrPhrJwBFnj8km-tOuR1pP__9V_rLRR-nIlPTA4ppZnnYkYkgtlov0J4CUX8DSwxxXPEQxuPT-i4xnvsgVq9RPeobtyhwjCHNzWNLCrl4uDi2t9zCYAmI3flixO32ZkgYKC8hwzP20qTGe4Q","p":"3EMQUPeC6JT7UkgkfZjLfVi40eJPO1XQQcVuTeCGsNW7AovaQu610jTVaB5YCdQV5qKJrUz794-Xj2w1gU9Q7r_xxbgKafeI6B5rq13ap4Np1lnRQ-xvF-eYE6V1z62cVpFWuQET4ukRCtnntIock0im5lMyEZEpDqNs-zpbGPE","q":"vRqB55d_mJgSInOuMiK1mOpfsZ606rw4MIpeMhlmA7LlAP-3n1uIaBZhHevEcvrEVUQHC-sFfJQTeKaGivO3oD0_mIDsR9XgiblPveVCq6mujXLFcIjXq_WxMfOQmPe8Fg-QU2q8lJL9Tgbz7XKZ1Ll7sDZ3IH2VZp8UDPvCDyU","dp":"qUtSiyjykVmRIdkZUv_Rx_IdfBR52Z1HiIX7Fhhw7hIYvwhHJhLb5Ul-jZxlBojgnHhpYa4-LDVNxIrjRRR1nEwjxFiEiJYdwGtBTmHA4ef7vSkj0xUy_iifltoiBxHljBQBmAjgBBQnaTO7B-TvubSps3ZWkXIFIJ8z8JUV18E","dq":"OvDnKpM67wn_JQPfeLr-1THAL_GivEN8VAzcvUrTVDXPURdjWWVDSAYpsRTKf3gP9--jLqDLbgANbZ6h8u9x_Zz5lIQioWVVfjfnVe3-cNkLkgUC60eLyYpj94jOOg-FbW7eclGjg7-o-kgKgaklr3s8xTjEurjJ91l_-2gBHY0","qi":"JkD7-8_vsWPueoe2SDpm7kH5VtkPqKeTm_wELuCSSxt5k9BEX3WNUZM-hRecAyCwyWi0ipHDi1vpI-EJfAxWL4jUIpS2onWbr6VCinTxJwh05F9vzGDyFgLeXszRQ88xJB9ZIbWtOYP7VO8XvjsoU2flDJmcZyR7VS_kv86UX3s"}"#;
#[cfg(feature = "rsa-oaep")]
const OAEP_PUBLIC_JWK: &str = r#"{"kty":"RSA","alg":"RSA-OAEP-256","n":"orRRoH0KpfluRVZxUTVQUUqKW0YuvvcXCU-h_ugiJOY3-XRtP3yv0xh42AMltu9aFwD2WQO0aUKeidbqyIRQl7WrOTGJ25JRLtincRoSU_rNIPecFegkfz0-QuRuSMmOJUov6XZTE6A-_48X4aApOXofomqNzib0kO2BKZYV2YFMItphBCjgnH2WWFlCZvXAIdD87KCNlFoSvoLeTR7Oa0wDFFtdNJXU7VQR64eNrwX9evw-Ca2g8RJkIvWQl1oZaYFvSGmLy7obTZyuedRg2Pn4Xnl1AF2bwixOWsD3waRdElaaYoB9O5oC5aUw53MGb0U9H1tMLpz3ggKD90K51Q","e":"AQAB"}"#;
#[cfg(feature = "rsa-oaep")]
const OAEP_MESSAGE: [u8; 20] = hexlower!("0000000000000000000000000000000000000000");
#[cfg(feature = "rsa-oaep")]
const OAEP_CIPHERTEXT: [u8; 256] = hexlower!(
    "207180c340658b5154ae45d2e4e7326a0997c683a26b595e536a29333c4b6614\
     9af85e029d5419a39e3a147b221516ffd86b6b4b66c3e0c4c49fe8c57a2f5c37\
     b8704b9b592b80db9cd788a4ed51ab4f0a1cbed63bd18d1f06a22f225866b0c2\
     c417cb23473b7ba4250b1353bd2e5b4f0f937cd2efe5fa38db3c295f7748b970\
     088657db4aa9a76e1ee6fbff166ec1861d00d085326c7384bdd1bc2f400d4f74\
     dbdfadaf3fdc46073e668573e02030b9eb5af58eb540c66677a771194479ec00\
     98d858a2ea45d0ba1e6b32440dfbac745000554d51a17684ca964b02a74d479f\
     1d432ef763ef4059715a4348cfe36a215359712f25b6977903be4adb92febbf6"
);

struct Component;

impl Guest for Component {
    async fn run() -> Result<String, String> {
        let mut passed: Vec<&'static str> = Vec::new();
        let mut check = async |name: &'static str, result: Result<()>| match result {
            Ok(()) => {
                passed.push(name);
                Ok(())
            }
            Err(err) => Err(format!("check '{name}' failed: {err:#}")),
        };

        check("hmac-key-export", hmac_key_export().await).await?;
        check("hmac-sha1-known-answer", hmac_sha1_known_answer().await).await?;
        check("digest-wrapper", digest_wrapper().await).await?;
        check("sha1-checked-or-declined", sha1_checked_or_declined().await).await?;
        check("aead-wrapper-seal", aead_wrapper_seal().await).await?;
        check("concurrent-seal-open", concurrent_seal_open().await).await?;
        check("key-wrap-tour", key_wrap_tour().await).await?;
        check(
            "aes-ctr-wrapper-roundtrip",
            aes_ctr_wrapper_roundtrip().await,
        )
        .await?;
        check("aes-cbc-known-answer", aes_cbc_known_answer().await).await?;
        check("ed25519-verify", ed25519_verify_check().await).await?;
        check(
            "ed25519-wrapper-roundtrip",
            ed25519_wrapper_roundtrip().await,
        )
        .await?;
        check(
            "ecdsa-verify-known-answer",
            ecdsa_verify_known_answer().await,
        )
        .await?;
        check("rsa-verify-known-answer", rsa_verify_known_answer().await).await?;
        #[cfg(feature = "rsa-oaep")]
        check("rsa-oaep-key-transport", rsa_oaep_key_transport().await).await?;
        check("hkdf-rfc5869-derive", hkdf_derive().await).await?;
        check("hkdf-sha1-derive", hkdf_sha1_derive().await).await?;
        check("pbkdf2-rfc7914-derive", pbkdf2_derive().await).await?;
        check("pbkdf2-sha1-derive", pbkdf2_sha1_derive().await).await?;
        check("x25519-agreement", x25519_agreement().await).await?;
        check("ecdh-agreement", ecdh_agreement().await).await?;
        check(
            "mac-datasource-equivalence",
            mac_datasource_equivalence().await,
        )
        .await?;
        check("read-error-precedence", read_error_precedence().await).await?;

        Ok(format!(
            "{} checks passed: {}",
            passed.len(),
            passed.join(", ")
        ))
    }
}

// --- mac -----------------------------------------------------------------

/// The MAC tour: `import` → `export` on an extractable key is the identity,
/// the imported key produces the RFC 4231 tag and verifies it, a payload
/// spanning several feed chunks round-trips (results must be
/// chunking-invariant), and a generated extractable key exports the hash's
/// block size of material (WebCrypto's `generateKey` default: 64 bytes for
/// SHA-256).
async fn hmac_key_export() -> Result<()> {
    use polymorph_webcrypto_guest::hmac_sha2;
    let full_grant = polymorph_webcrypto_guest::MacKeyOptions {
        sign: true,
        verify: true,
        extractable: true,
    };
    let key = hmac_sha2::import_key_raw(Sha2Variant::Sha256, HMAC_KEY, full_grant)
        .await
        .context("import-key-raw")?;
    let exported = key
        .export_key_raw()
        .await
        .context("export of extractable key")?;
    ensure!(
        exported == HMAC_KEY,
        "exported key material: got {}",
        hex(&exported)
    );
    let tag = key.sign(HMAC_DATA).await.context("sign")?;
    ensure!(
        tag == HMAC_TAG,
        "wrapper sign tag: got {}, want {}",
        hex(&tag),
        hex(&HMAC_TAG)
    );
    key.verify(HMAC_DATA, &tag)
        .await
        .context("wrapper verify")?;

    // A borrowed payload spanning several of the wrapper's feed chunks
    // round-trips sign→verify (the wrapper feeds borrowed sources
    // incrementally; the result must be chunking-invariant).
    let big: Vec<u8> = (0..=255u8).cycle().take(3 * 8192 + 11).collect();
    let tag = key
        .sign(&big[..])
        .await
        .context("wrapper sign (multi-chunk)")?;
    key.verify(&big[..], tag)
        .await
        .context("wrapper verify (multi-chunk)")?;

    let generated = hmac_sha2::generate_key(Sha2Variant::Sha256, None, full_grant)
        .await
        .context("generate-key")?;
    let exported = generated
        .export_key_raw()
        .await
        .context("export of generated key")?;
    ensure!(
        exported.len() == 64,
        "generated key length: got {}, want 64",
        exported.len()
    );
    Ok(())
}

// --- digest -------------------------------------------------------

/// The FIPS 180-2 "abc" SHA-256 example digest.
const SHA256_ABC: [u8; 32] =
    hexlower!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

/// The digest tour: the `Digest` wrapper computes the FIPS 180-2 "abc"
/// example digest, and the resource is reusable — a second compute agrees.
async fn digest_wrapper() -> Result<()> {
    let digest = polymorph_webcrypto_guest::sha2::make_digest(Sha2Variant::Sha256)?;
    ensure!(
        digest.algorithm_name() == "SHA-256",
        "algorithm-name: got {}",
        digest.algorithm_name()
    );
    let got = digest.compute(b"abc").await?;
    ensure!(got == SHA256_ABC, "computed digest: got {}", hex(&got));
    let again = digest.compute(b"abc").await?;
    ensure!(
        again == SHA256_ABC,
        "recomputed digest: got {}",
        hex(&again)
    );
    Ok(())
}

/// The `sha1_checked` SDK wrappers: an implementation either serves the
/// checked SHA-1 constructors — both collision postures then compute the
/// FIPS 180 "abc" digest, attack-free input being posture-independent —
/// or declines them `unsupported`, the fail-closed posture of
/// browser-backed hosts (both constructors must agree).
async fn sha1_checked_or_declined() -> Result<()> {
    use polymorph_webcrypto_guest::{sha1_checked, Error};
    let minted = (
        sha1_checked::make_rejecting_digest(),
        sha1_checked::make_mitigating_digest(),
    );
    let (rejecting, mitigating) = match minted {
        (Err(Error::Unsupported(_)), Err(Error::Unsupported(_))) => return Ok(()),
        (rejecting, mitigating) => (
            rejecting.context("make-rejecting-digest")?,
            mitigating.context("make-mitigating-digest")?,
        ),
    };
    let abc_sha1 = hexlower!("a9993e364706816aba3e25717850c26c9cd0d89d");
    for (what, digest) in [("rejecting", &rejecting), ("mitigating", &mitigating)] {
        let got = digest
            .compute(b"abc")
            .await
            .with_context(|| format!("compute ({what})"))?;
        ensure!(got == abc_sha1, "{what} digest: got {}", hex(&got));
    }
    Ok(())
}

// --- aead -----------------------------------------------------------------

/// The AEAD tour, and the library's `Aead` wrapper:
/// `seal` is the one operation whose result may arrive before its input is
/// consumed, so its `Seal` collects concurrently with feeding rather than
/// awaiting the operation and reading afterwards. The single-shot seal is
/// checked against the NIST GCM vector's ciphertext‖tag.
///
/// Two `Seal`s under one `join!` is the shape the package's making-progress
/// rule asks for, and the reason `Seal` is a `Future` rather than an
/// `async fn`'s anonymous one.
async fn aead_wrapper_seal() -> Result<()> {
    use polymorph_webcrypto_guest::aes_gcm;

    let seal_open = polymorph_webcrypto_guest::AeadKeyOptions {
        seal: true,
        open: true,
        ..Default::default()
    };
    let key = aes_gcm::import_key_raw(AesVariant::Aes256, GCM_KEY, seal_open)
        .await
        .context("import-key-raw")?;
    let nonce = GCM_IV;
    let plaintext = GCM_PLAINTEXT;
    let aad = GCM_AAD;

    let sealed = key
        .seal(&nonce[..], &aad[..], &plaintext[..])
        .await
        .context("wrapper seal")?;
    ensure!(
        sealed == [GCM_CIPHERTEXT.as_slice(), GCM_TAG.as_slice()].concat(),
        "wrapper sealed message: got {}",
        hex(&sealed)
    );

    // A payload spanning several of the wrapper's feed chunks: the collect
    // runs alongside the feed, so this must not depend on the whole input
    // being taken before any output is produced.
    let big: Vec<u8> = (0..=255u8).cycle().take(3 * 8192 + 11).collect();
    let (first, second) = futures::join!(
        key.seal(&nonce[..], &aad[..], &big[..]),
        key.seal(&nonce[..], &aad[..], &big[..]),
    );
    let first = first.context("wrapper seal (multi-chunk)")?;
    let second = second.context("wrapper seal (concurrent)")?;
    ensure!(first == second, "concurrent seals of one payload differ");
    ensure!(
        first.len() == big.len() + 16,
        "sealed length is plaintext plus tag: got {}, want {}",
        first.len(),
        big.len() + 16
    );
    Ok(())
}

/// Eight seal→open round trips in flight at once, each draining its own
/// streams — the making-progress shape the package asks callers for.
///
/// Correctness is asserted here; the *contended* case is the Wasmtime
/// integration test that reruns this demo with a pool smaller than the
/// concurrency (examples/wasmtime-demo/tests/demo.rs), where this check
/// hangs if an implementation stops releasing an operation's capacity when
/// its output is drained. On other hosts the pool is ample and this is a
/// plain concurrency check.
async fn concurrent_seal_open() -> Result<()> {
    use polymorph_webcrypto_guest::aes_gcm;

    let key = aes_gcm::generate_key(
        AesVariant::Aes256,
        polymorph_webcrypto_guest::AeadKeyOptions {
            seal: true,
            open: true,
            ..Default::default()
        },
    )
    .await
    .context("generate-key")?;

    async fn round_trip(key: &polymorph_webcrypto_guest::Aead, lane: u8) -> Result<()> {
        let mut nonce = [0u8; 12];
        nonce[0] = lane;
        let payload: Vec<u8> = (0..2048u32).map(|i| (i as u8).wrapping_add(lane)).collect();
        let sealed = key
            .seal(&nonce[..], &b"concurrent"[..], &payload[..])
            .await
            .with_context(|| format!("seal (lane {lane})"))?;
        let opened = key
            .open(&nonce[..], &b"concurrent"[..], &sealed[..])
            .await
            .with_context(|| format!("open (lane {lane})"))?
            .collect()
            .await;
        ensure!(opened == payload, "lane {lane} round trip differs");
        Ok(())
    }

    let lanes = futures::join!(
        round_trip(&key, 0),
        round_trip(&key, 1),
        round_trip(&key, 2),
        round_trip(&key, 3),
        round_trip(&key, 4),
        round_trip(&key, 5),
        round_trip(&key, 6),
        round_trip(&key, 7),
    );
    let (a, b, c, d, e, f, g, h) = lanes;
    a.and(b).and(c).and(d).and(e).and(f).and(g).and(h)
}

/// HMAC-SHA-1 through its SDK wrappers against RFC 2202 case 1: the
/// imported key signs "Hi There" to the published tag, verifies it, and
/// rejects a corrupted one.
async fn hmac_sha1_known_answer() -> Result<()> {
    use polymorph_webcrypto_guest::hmac_sha1;
    let key = hmac_sha1::import_key_raw(
        vec![0x0b; 20],
        polymorph_webcrypto_guest::MacKeyOptions {
            sign: true,
            verify: true,
            extractable: false,
        },
    )
    .await
    .context("import-key-raw")?;
    let tag = key.sign(&b"Hi There"[..]).await.context("sign")?;
    ensure!(
        tag == hexlower!("b617318655057264e28bc0b6fb378c8ef146be00"),
        "HMAC-SHA-1 tag: got {}",
        hex(&tag)
    );
    key.verify(&b"Hi There"[..], &tag).await.context("verify")?;
    let mut corrupted = tag.clone();
    corrupted[0] ^= 1;
    ensure!(
        key.verify(&b"Hi There"[..], &corrupted).await.is_err(),
        "corrupted tag verified"
    );
    Ok(())
}

// --- cipher ----------------------------------------------------------------

/// The cipher tour: the `CipherKey` wrapper end to end — generate through
/// `aes_ctr`, encrypt (a lazy [`Seal`](polymorph_webcrypto_guest::Seal)),
/// decrypt, and compare.
async fn aes_ctr_wrapper_roundtrip() -> Result<()> {
    use polymorph_webcrypto_guest::{aes_ctr, CipherKeyOptions};
    let key = aes_ctr::generate_key(
        aes_ctr::AesVariant::Aes256,
        CipherKeyOptions {
            encrypt: true,
            decrypt: true,
            wrap: false,
            unwrap: false,
            extractable: false,
        },
    )
    .await?;
    let plaintext = &b"counter-mode wrapper payload"[..];
    let iv = [0u8; 16];
    let ciphertext = key.encrypt(&iv[..], Some(64), plaintext).await?;
    ensure!(ciphertext != plaintext, "ciphertext equals plaintext");
    let decrypted = key
        .decrypt(&iv[..], Some(64), ciphertext)
        .await?
        .collect()
        .await;
    ensure!(decrypted == plaintext, "round trip disagreed");
    Ok(())
}

/// AES-CBC through its SDK wrappers against NIST SP 800-38A F.2.1's
/// first block: the imported key encrypts the block to the published
/// ciphertext (followed by one full PKCS#7 padding block), and the
/// ciphertext decrypts back to the block.
async fn aes_cbc_known_answer() -> Result<()> {
    use polymorph_webcrypto_guest::{aes_cbc, CipherKeyOptions};
    let key = aes_cbc::import_key_raw(
        aes_cbc::AesVariant::Aes128,
        hexlower!("2b7e151628aed2a6abf7158809cf4f3c"),
        CipherKeyOptions {
            encrypt: true,
            decrypt: true,
            wrap: false,
            unwrap: false,
            extractable: false,
        },
    )
    .await
    .context("import-key-raw")?;
    let iv = hexlower!("000102030405060708090a0b0c0d0e0f");
    let plaintext = hexlower!("6bc1bee22e409f96e93d7e117393172a");
    let ciphertext = key.encrypt(&iv[..], None, &plaintext[..]).await?;
    ensure!(
        ciphertext.len() == 32 && ciphertext[..16] == hexlower!("7649abac8119b246cee98e9b12e9197d"),
        "CBC ciphertext: got {}",
        hex(&ciphertext)
    );
    let decrypted = key
        .decrypt(&iv[..], None, ciphertext)
        .await?
        .collect()
        .await;
    ensure!(decrypted == plaintext, "round trip disagreed");
    Ok(())
}

// --- signature ---------------------------------------------------------------

/// An imported public key reports its algorithm through the getters,
/// verifies the RFC 8032 signature, and rejects a corrupted one with
/// `authentication-failed`.
async fn ed25519_verify_check() -> Result<()> {
    use polymorph_webcrypto_guest::ed25519;
    let key = ed25519::import_verifying_key_raw(ED25519_PUBLIC)
        .await
        .context("import-verifying-key-raw")?;
    ensure!(
        key.algorithm_name() == "Ed25519",
        "verifying-key.algorithm-name: got {}",
        key.algorithm_name()
    );

    let mut sig = ED25519_SIG.to_vec();
    key.verify(ED25519_MESSAGE, sig.clone())
        .await
        .context("correct signature did not verify")?;

    sig[0] ^= 0x01;
    expect_error!(
        key.verify(ED25519_MESSAGE, sig).await,
        Error::AuthenticationFailed,
        "corrupted signature verified",
    )
}

/// The signature wrappers end to end: generate through `ed25519`, sign
/// through `SigningKey`, verify through `VerifyingKey`, and fail closed on
/// a tampered signature.
async fn ed25519_wrapper_roundtrip() -> Result<()> {
    use polymorph_webcrypto_guest::{ed25519, SigningKeyOptions};
    let (signing, verifying) = ed25519::generate_key(SigningKeyOptions {
        sign: true,
        extractable: false,
    })
    .await?;
    ensure!(
        !signing.extractable(),
        "non-extractable signing key reports extractable"
    );
    let payload = &b"wrapper-signed payload"[..];
    let mut sig = signing.sign(payload).await?;
    ensure!(
        sig.len() == 64,
        "signature length: got {}, want 64",
        sig.len()
    );
    verifying
        .verify(payload, sig.clone())
        .await
        .context("fresh signature did not verify")?;
    sig[0] ^= 0x01;
    expect_error!(
        verifying.verify(payload, sig).await,
        Error::AuthenticationFailed,
        "tampered signature verified",
    )
}

/// The RFC 6979 known answer: an imported P-256 public key reports its
/// variant through the getters, verifies the deterministic signature over
/// "sample", and rejects a corrupted one.
async fn ecdsa_verify_known_answer() -> Result<()> {
    use polymorph_webcrypto_guest::ecdsa::{self, EcdsaVariant};
    let mut point = vec![0x04];
    point.extend(ECDSA_PUBLIC_X);
    point.extend(ECDSA_PUBLIC_Y);
    let key = ecdsa::import_verifying_key_raw(EcdsaVariant::P256Sha256, point)
        .await
        .context("import-verifying-key-raw")?;
    ensure!(
        key.algorithm_name() == "ECDSA",
        "verifying-key.algorithm-name: got {}",
        key.algorithm_name()
    );
    ensure!(
        key.algorithm_curve().as_deref() == Some("P-256"),
        "verifying-key.algorithm-curve: got {:?}",
        key.algorithm_curve()
    );
    ensure!(
        key.algorithm_hash().as_deref() == Some("SHA-256"),
        "verifying-key.algorithm-hash: got {:?}",
        key.algorithm_hash()
    );

    let mut sig = ECDSA_SIG_R.to_vec();
    sig.extend(ECDSA_SIG_S);
    key.verify(ECDSA_MESSAGE, sig.clone())
        .await
        .context("known-answer signature did not verify")?;

    sig[0] ^= 0x01;
    expect_error!(
        key.verify(ECDSA_MESSAGE, sig).await,
        Error::AuthenticationFailed,
        "corrupted signature verified",
    )
}

/// The Wycheproof known answers, one per RSA signature algorithm over the
/// vector files' shared 2048-bit key: an SPKI-imported key reports its
/// parameterization through the getters — the modulus length included —
/// verifies the vector's valid signature, and rejects a corrupted one.
async fn rsa_verify_known_answer() -> Result<()> {
    use polymorph_webcrypto_guest::rsa_pss;
    use polymorph_webcrypto_guest::rsassa_pkcs1_v15::{self, RsaVariant};

    // rsa_signature_2048_sha256_test.json tcId 1.
    let key = rsassa_pkcs1_v15::import_verifying_key_spki(RsaVariant::Sha256, RSA_SPKI)
        .await
        .context("rsassa-pkcs1-v15 import-verifying-key-spki")?;
    ensure!(
        key.algorithm_name() == "RSASSA-PKCS1-v1_5",
        "verifying-key.algorithm-name: got {}",
        key.algorithm_name()
    );
    ensure!(
        key.algorithm_hash().as_deref() == Some("SHA-256"),
        "verifying-key.algorithm-hash: got {:?}",
        key.algorithm_hash()
    );
    ensure!(
        key.algorithm_length() == Some(2048),
        "verifying-key.algorithm-length: got {:?}",
        key.algorithm_length()
    );
    let mut sig = RSA_PKCS1_SIG.to_vec();
    key.verify(RSA_MESSAGE, sig.clone())
        .await
        .context("known-answer RSASSA-PKCS1-v1_5 signature did not verify")?;
    sig[0] ^= 0x01;
    expect_error!(
        key.verify(RSA_MESSAGE, sig).await,
        Error::AuthenticationFailed,
        "corrupted RSASSA-PKCS1-v1_5 signature verified",
    )?;

    // rsa_pss_2048_sha256_mgf1_32_test.json tcId 1 (sLen 32, bound at mint).
    let key = rsa_pss::import_verifying_key_spki(RsaVariant::Sha256, 32, RSA_SPKI)
        .await
        .context("rsa-pss import-verifying-key-spki")?;
    ensure!(
        key.algorithm_name() == "RSA-PSS",
        "verifying-key.algorithm-name: got {}",
        key.algorithm_name()
    );
    ensure!(
        key.algorithm_hash().as_deref() == Some("SHA-256"),
        "verifying-key.algorithm-hash: got {:?}",
        key.algorithm_hash()
    );
    ensure!(
        key.algorithm_length() == Some(2048),
        "verifying-key.algorithm-length: got {:?}",
        key.algorithm_length()
    );
    let mut sig = RSA_PSS_SIG.to_vec();
    key.verify(RSA_MESSAGE, sig.clone())
        .await
        .context("known-answer RSA-PSS signature did not verify")?;
    sig[0] ^= 0x01;
    expect_error!(
        key.verify(RSA_MESSAGE, sig).await,
        Error::AuthenticationFailed,
        "corrupted RSA-PSS signature verified",
    )
}

/// The RSA-OAEP key-transport tour, one call per `rsa_oaep` constructor:
/// the Wycheproof known answer decrypts under both private-key imports
/// (PKCS#8 and the file's full-CRT JWK), the public half imported as the
/// SPKI the signature checks carry (same modulus) and as a public JWK
/// encrypts back to the same private key, a ciphertext decrypts only
/// under the label it was encrypted with, and a generated pair
/// round-trips (RFC 8017's OAEP is randomized, so generation has no
/// known-answer form — the round trip is the check).
#[cfg(feature = "rsa-oaep")]
async fn rsa_oaep_key_transport() -> Result<()> {
    use polymorph_webcrypto_guest::rsa_oaep::{self, RsaModulus, RsaVariant};
    use polymorph_webcrypto_guest::DecryptionKeyOptions;

    let grants = DecryptionKeyOptions {
        decrypt: true,
        unwrap: false,
        extractable: false,
    };

    // rsa_oaep_2048_sha256_mgf1sha256_test.json tcId 2, under both
    // private-key encodings.
    let dec = rsa_oaep::import_decryption_key_pkcs8(RsaVariant::Sha256, OAEP_PKCS8, grants)
        .await
        .context("rsa-oaep-decrypt import-decryption-key-pkcs8")?;
    let plaintext = dec.decrypt(None, OAEP_CIPHERTEXT).await?;
    ensure!(
        plaintext == OAEP_MESSAGE,
        "OAEP known answer (PKCS#8 import): got {}",
        hex(&plaintext)
    );
    let dec_jwk = rsa_oaep::import_decryption_key_jwk(RsaVariant::Sha256, OAEP_PRIVATE_JWK, grants)
        .await
        .context("rsa-oaep-decrypt import-decryption-key-jwk")?;
    let plaintext = dec_jwk.decrypt(None, OAEP_CIPHERTEXT).await?;
    ensure!(
        plaintext == OAEP_MESSAGE,
        "OAEP known answer (JWK import): got {}",
        hex(&plaintext)
    );

    // The public half arrives independently of the private key, in both
    // import encodings; each encrypts to the vector's private key.
    let enc = rsa_oaep::import_encryption_key_spki(RsaVariant::Sha256, RSA_SPKI)
        .await
        .context("rsa-oaep-encrypt import-encryption-key-spki")?;
    let ct = enc.encrypt(None, *b"oaep spki transport").await?;
    ensure!(
        dec.decrypt(None, ct).await? == b"oaep spki transport",
        "SPKI-imported public key's ciphertext did not round-trip"
    );
    let enc_jwk = rsa_oaep::import_encryption_key_jwk(RsaVariant::Sha256, OAEP_PUBLIC_JWK)
        .await
        .context("rsa-oaep-encrypt import-encryption-key-jwk")?;
    let label = b"transport label";
    let ct = enc_jwk.encrypt(Some(label), *b"oaep jwk transport").await?;
    ensure!(
        dec.decrypt(Some(label), ct.clone()).await? == b"oaep jwk transport",
        "JWK-imported public key's ciphertext did not round-trip"
    );
    expect_error!(
        dec.decrypt(Some(b"wrong label"), ct).await,
        Error::AuthenticationFailed,
        "a ciphertext decrypted under a label it was not encrypted with",
    )?;

    // A generated pair round-trips.
    let (dec_gen, enc_gen) = rsa_oaep::generate_key(RsaVariant::Sha256, RsaModulus::M2048, grants)
        .await
        .context("rsa-oaep-decrypt generate-key")?;
    let ct = enc_gen.encrypt(None, *b"generated pair").await?;
    ensure!(
        dec_gen.decrypt(None, ct).await? == b"generated pair",
        "generated OAEP pair failed to round-trip"
    );
    Ok(())
}

// --- derivation --------------------------------------------------------------

/// HKDF-SHA-256 against RFC 5869 test case 1, through the SDK wrappers:
/// import the IKM, prepare with the vector's salt and info, and derive its
/// 42-byte OKM; a null-length derive must fail (a KDF has no natural
/// output length); the same input then mints an HMAC key that round-trips
/// sign/verify.
async fn hkdf_derive() -> Result<()> {
    use polymorph_webcrypto_guest::{hkdf, hkdf_sha2, DeriveOptions, MacKeyOptions};
    let options = DeriveOptions {
        derive_bits: true,
        derive_key: true,
    };
    let ikm = hkdf::import_ikm(vec![0x0b; 22], options).await?;
    let input = hkdf_sha2::prepare(
        Sha2Variant::Sha256,
        &ikm,
        hexlower!("000102030405060708090a0b0c"),
        hexlower!("f0f1f2f3f4f5f6f7f8f9"),
    )
    .await?;
    let okm = input.derive_bits(Some(42 * 8)).await?;
    ensure!(
        okm == hexlower!(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        ),
        "OKM mismatch: got {}",
        hex(&okm)
    );
    ensure!(
        input.derive_bits(None).await.is_err(),
        "null-length derive on a KDF source succeeded"
    );

    let mac = polymorph_webcrypto_guest::hmac_sha2::derive_key(
        Sha2Variant::Sha256,
        &input,
        None,
        MacKeyOptions {
            sign: true,
            verify: true,
            extractable: false,
        },
    )
    .await?;
    let payload = &b"derived-key payload"[..];
    let tag = mac.sign(payload).await?;
    mac.verify(payload, tag)
        .await
        .context("derived HMAC key did not round-trip")
}

/// PBKDF2-HMAC-SHA-256 against RFC 7914 §11's first PBKDF2 vector
/// (P="passwd", S="salt", c=1, dkLen=64), through the SDK wrappers.
async fn pbkdf2_derive() -> Result<()> {
    use polymorph_webcrypto_guest::{pbkdf2, pbkdf2_sha2, DeriveOptions};
    let options = DeriveOptions {
        derive_bits: true,
        derive_key: false,
    };
    let password = pbkdf2::import_password(b"passwd", options).await?;
    let input = pbkdf2_sha2::prepare(Sha2Variant::Sha256, &password, b"salt", 1).await?;
    let dk = input.derive_bits(Some(64 * 8)).await?;
    ensure!(
        dk == hexlower!(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
             49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        ),
        "derived key mismatch: got {}",
        hex(&dk)
    );
    Ok(())
}

/// HKDF-SHA-1 through its SDK wrappers against RFC 5869 A.4 (test case
/// 4): the imported IKM derives the published 42-byte OKM.
async fn hkdf_sha1_derive() -> Result<()> {
    use polymorph_webcrypto_guest::{hkdf, hkdf_sha1, DeriveOptions};
    let options = DeriveOptions {
        derive_bits: true,
        derive_key: false,
    };
    let ikm = hkdf::import_ikm(vec![0x0b; 11], options).await?;
    let input = hkdf_sha1::prepare(
        &ikm,
        hexlower!("000102030405060708090a0b0c"),
        hexlower!("f0f1f2f3f4f5f6f7f8f9"),
    )
    .await?;
    let okm = input.derive_bits(Some(42 * 8)).await?;
    ensure!(
        okm == hexlower!(
            "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"
        ),
        "OKM mismatch: got {}",
        hex(&okm)
    );
    Ok(())
}

/// PBKDF2-HMAC-SHA-1 through its SDK wrappers against RFC 6070's c=2
/// vector (P="password", S="salt", dkLen=20).
async fn pbkdf2_sha1_derive() -> Result<()> {
    use polymorph_webcrypto_guest::{pbkdf2, pbkdf2_sha1, DeriveOptions};
    let options = DeriveOptions {
        derive_bits: true,
        derive_key: false,
    };
    let password = pbkdf2::import_password(b"password", options).await?;
    let input = pbkdf2_sha1::prepare(&password, b"salt", 2).await?;
    let dk = input.derive_bits(Some(20 * 8)).await?;
    ensure!(
        dk == hexlower!("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
        "derived key mismatch: got {}",
        hex(&dk)
    );
    Ok(())
}

/// X25519 agreement through the SDK wrappers: two generated keypairs
/// agree in both directions on the same 32-byte secret, and both agreed
/// inputs chain into HKDF (WebCrypto's `deriveKey(ECDH -> HKDF)` shape)
/// to the same bits.
async fn x25519_agreement() -> Result<()> {
    use polymorph_webcrypto_guest::{hkdf_sha2, x25519, AgreementKeyOptions};
    let options = AgreementKeyOptions {
        derive_bits: true,
        derive_key: true,
        extractable: false,
    };
    let (a_secret, a_public) = x25519::generate_key(options).await?;
    let (b_secret, b_public) = x25519::generate_key(options).await?;
    let ab = a_secret.agree(&b_public).await?;
    let ba = b_secret.agree(&a_public).await?;
    let ab_bits = ab.derive_bits(None).await?;
    let ba_bits = ba.derive_bits(None).await?;
    ensure!(
        ab_bits.len() == 32,
        "shared secret is {} bytes",
        ab_bits.len()
    );
    ensure!(ab_bits == ba_bits, "shared secrets disagree by direction");

    let a_input = hkdf_sha2::prepare_from(Sha2Variant::Sha256, &ab, b"salt", b"info").await?;
    let b_input = hkdf_sha2::prepare_from(Sha2Variant::Sha256, &ba, b"salt", b"info").await?;
    ensure!(
        a_input.derive_bits(Some(256)).await? == b_input.derive_bits(Some(256)).await?,
        "chained derivations disagree by direction"
    );
    Ok(())
}

/// ECDH agreement through the SDK wrappers, the same shape as
/// `x25519-agreement` per curve: two generated keypairs agree in both
/// directions on the same field-size secret (32 bytes for P-256, 48 for
/// P-384), and on P-256 both agreed inputs chain into HKDF to the same
/// bits.
async fn ecdh_agreement() -> Result<()> {
    use polymorph_webcrypto_guest::ecdh::{self, EcdhVariant};
    use polymorph_webcrypto_guest::{hkdf_sha2, AgreementKeyOptions};
    let options = AgreementKeyOptions {
        derive_bits: true,
        derive_key: true,
        extractable: false,
    };

    for (variant, field_size) in [(EcdhVariant::P256, 32), (EcdhVariant::P384, 48)] {
        let (a_secret, a_public) = ecdh::generate_key(variant, options).await?;
        let (b_secret, b_public) = ecdh::generate_key(variant, options).await?;
        let ab = a_secret.agree(&b_public).await?;
        let ba = b_secret.agree(&a_public).await?;
        let ab_bits = ab.derive_bits(None).await?;
        let ba_bits = ba.derive_bits(None).await?;
        ensure!(
            ab_bits.len() == field_size,
            "{variant:?} shared secret is {} bytes, want {field_size}",
            ab_bits.len()
        );
        ensure!(
            ab_bits == ba_bits,
            "{variant:?} shared secrets disagree by direction"
        );

        if variant == EcdhVariant::P256 {
            let a_input =
                hkdf_sha2::prepare_from(Sha2Variant::Sha256, &ab, b"salt", b"info").await?;
            let b_input =
                hkdf_sha2::prepare_from(Sha2Variant::Sha256, &ba, b"salt", b"info").await?;
            ensure!(
                a_input.derive_bits(Some(256)).await? == b_input.derive_bits(Some(256)).await?,
                "chained derivations disagree by direction"
            );
        }
    }
    Ok(())
}

// --- byte-source plumbing ------------------------------------------------------

/// Every `DataSource` variant produces the RFC 4231 tag: borrowed and
/// owned buffers, a multi-chunk `Buf` (feature `bytes`), an incremental
/// reader (feature `futures-io`), and a passed-through stream. The
/// feature-gated feed loops execute only here.
async fn mac_datasource_equivalence() -> Result<()> {
    use polymorph_webcrypto_guest::{hmac_sha2, DataSource, MacKeyOptions};
    let key = hmac_sha2::import_key_raw(
        Sha2Variant::Sha256,
        HMAC_KEY,
        MacKeyOptions {
            sign: true,
            verify: true,
            extractable: false,
        },
    )
    .await?;
    let expected = HMAC_TAG;

    let borrowed = key.sign(HMAC_DATA).await?;
    ensure!(
        borrowed == expected,
        "borrowed source: got {}",
        hex(&borrowed)
    );

    let owned = key.sign(HMAC_DATA.to_vec()).await?;
    ensure!(owned == expected, "owned source: got {}", hex(&owned));

    let (head, tail) = HMAC_DATA.split_at(9);
    let buf = bytes::Buf::chain(head, tail);
    let bufed = key.sign(DataSource::from_buf(buf)).await?;
    ensure!(bufed == expected, "buf source: got {}", hex(&bufed));

    let read = key
        .sign(DataSource::from_reader(ChunkReader::new(HMAC_DATA, 7)))
        .await?;
    ensure!(read == expected, "reader source: got {}", hex(&read));

    let (tx, rx) = wit_stream::new();
    let feed = async move {
        let mut tx = tx;
        // Dropping the writer ends the stream; the sign resolves only then.
        tx.write_all(HMAC_DATA.to_vec()).await
    };
    let (streamed, leftover) = futures::join!(key.sign(rx), feed);
    ensure!(leftover.is_empty(), "the operation left input unread");
    let streamed = streamed?;
    ensure!(
        streamed == expected,
        "stream source: got {}",
        hex(&streamed)
    );
    Ok(())
}

/// A failing `from_reader` source surfaces as `Error::Read`, taking
/// precedence over the operation's own outcome: the operation only saw a
/// truncated input.
async fn read_error_precedence() -> Result<()> {
    use polymorph_webcrypto_guest::{hmac_sha2, DataSource, MacKeyOptions};
    let key = hmac_sha2::import_key_raw(
        Sha2Variant::Sha256,
        HMAC_KEY,
        MacKeyOptions {
            sign: true,
            verify: true,
            extractable: false,
        },
    )
    .await?;
    let result = key
        .sign(DataSource::from_reader(FailingReader { fed: false }))
        .await;
    ensure!(
        matches!(result, Err(Error::Read(_))),
        "expected Error::Read, got {result:?}"
    );
    Ok(())
}

/// Yields `data` in `chunk`-byte reads — a well-behaved incremental
/// reader.
struct ChunkReader {
    data: &'static [u8],
    chunk: usize,
}

impl ChunkReader {
    fn new(data: &'static [u8], chunk: usize) -> Self {
        Self { data, chunk }
    }
}

impl futures_io::AsyncRead for ChunkReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let n = self.chunk.min(self.data.len()).min(buf.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        std::task::Poll::Ready(Ok(n))
    }
}

/// Yields one chunk, then fails — the truncating producer whose failure
/// `Error::Read` must report over the operation's outcome.
struct FailingReader {
    fed: bool,
}

impl futures_io::AsyncRead for FailingReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.fed {
            return std::task::Poll::Ready(Err(std::io::Error::other("reader failed midway")));
        }
        self.fed = true;
        let n = buf.len().min(4);
        buf[..n].copy_from_slice(&[0xAB; 4][..n]);
        std::task::Poll::Ready(Ok(n))
    }
}

// --- small utilities ---------------------------------------------------------

/// One key-wrap tour: the RFC 3394 known answer through `kw-key.wrap`, the
/// unwrap half minting the key data back out through the raw unwrap mint,
/// and the AEAD wrap identity (`wrap` equals `seal` over the exported
/// bytes). The rejection surface and domains are the conformance suites'
/// job.
async fn key_wrap_tour() -> Result<()> {
    use polymorph_webcrypto_guest::{aes_gcm, aes_kw, hmac_sha2, KwKeyOptions, MacKeyOptions};

    let kek = aes_kw::import_key_raw(
        AesVariant::Aes128,
        KW_KEK,
        KwKeyOptions {
            wrap: true,
            unwrap: true,
            extractable: false,
        },
    )
    .await
    .context("aes-kw import-key-raw")?;
    ensure!(
        kek.algorithm_name() == "AES-KW",
        "kw-key.algorithm-name: got {}",
        kek.algorithm_name()
    );

    // The key data enters the wrap path as an extractable key's material.
    let payload = hmac_sha2::import_key_raw(
        Sha2Variant::Sha256,
        KW_DATA,
        MacKeyOptions {
            sign: true,
            verify: false,
            extractable: true,
        },
    )
    .await
    .context("payload import")?;
    let wrapped = kek
        .wrap(payload.to_wrap_input_raw().await.context("to-wrap-input")?)
        .await
        .context("kw-key.wrap")?;
    ensure!(
        wrapped == KW_WRAPPED,
        "RFC 3394 wire format: got {}",
        hex(&wrapped)
    );

    // Unwrap and mint the key data back out: the minted key must agree
    // with the original on a tag.
    let minted = hmac_sha2::unwrap_key_raw(
        Sha2Variant::Sha256,
        kek.unwrap(wrapped).await.context("kw-key.unwrap")?,
        MacKeyOptions {
            sign: true,
            verify: false,
            extractable: false,
        },
    )
    .await
    .context("hmac-sha2.unwrap-key-raw")?;
    let via_wrap = minted.sign(HMAC_DATA).await.context("minted sign")?;
    let direct = payload.sign(HMAC_DATA).await.context("payload sign")?;
    ensure!(
        via_wrap == direct,
        "the unwrapped key disagrees with the original"
    );

    // The AEAD wrap identity: `wrap` is byte-identical to sealing the
    // exported bytes.
    let aead_kek = aes_gcm::import_key_raw(
        AesVariant::Aes256,
        GCM_KEY,
        polymorph_webcrypto_guest::AeadKeyOptions {
            seal: true,
            wrap: true,
            ..Default::default()
        },
    )
    .await
    .context("aead kek import")?;
    let nonce = GCM_IV;
    let wrapped = aead_kek
        .wrap(
            nonce,
            Vec::new(),
            None,
            payload.to_wrap_input_raw().await.context("to-wrap-input")?,
        )
        .await
        .context("aead-key.wrap")?;
    let sealed = aead_kek
        .seal(&nonce[..], &[][..], &payload.export_key_raw().await?[..])
        .await
        .context("seal comparison")?;
    ensure!(
        wrapped == sealed,
        "aead wrap must equal seal over the export"
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

export!(Component);
