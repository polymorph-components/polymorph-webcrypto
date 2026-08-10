# Test matrix

| Case | composed | deltic-browser | deltic-deno | jco-browser | jco-node | wasmtime-rustcrypto |
| --- | --- | --- | --- | --- | --- | --- |
| aes-cbc (254 cases) | pass | pass | pass | pass | pass | pass |
| aes-ctr (10 cases) | pass | pass | pass | pass | pass | pass |
| aes-gcm (485 cases) | pass | pass | 455 pass, 30 xfail | pass | pass | pass |
| aes-kw (110 cases) | pass | pass | pass | pass | pass | pass |
| ecdh/contract/grants | pass | pass | pass | pass | pass | pass |
| ecdh-p256 (1097 cases) | pass | pass | pass | pass | pass | pass |
| ecdh-p384 (2408 cases) | pass | pass | pass | pass | pass | pass |
| ecdsa-p256-sha256 (609 cases) | pass | pass | pass | pass | pass | pass |
| ecdsa-p256-sha512 (816 cases) | pass | pass | pass | pass | pass | pass |
| ecdsa-p384-sha384 (666 cases) | pass | pass | pass | pass | pass | pass |
| ecdsa-p384-sha512 (778 cases) | pass | pass | pass | pass | pass | pass |
| ed25519 (336 cases) | pass | pass | pass | pass | pass | pass |
| hkdf-sha1 (87 cases) | pass | pass | pass | pass | pass | pass |
| hkdf-sha2/contract/grants | pass | pass | pass | pass | pass | pass |
| hkdf-sha256 (86 cases) | pass | pass | pass | pass | pass | pass |
| hkdf-sha384 (83 cases) | pass | pass | pass | pass | pass | pass |
| hkdf-sha512 (83 cases) | pass | pass | pass | pass | pass | pass |
| hmac-sha1 (152 cases) | pass | pass | pass | pass | pass | pass |
| hmac-sha2 (15 cases) | pass | pass | pass | pass | pass | pass |
| hmac-sha256 (147 cases) | pass | pass | pass | pass | pass | pass |
| hmac-sha384 (147 cases) | pass | pass | pass | pass | pass | pass |
| hmac-sha512 (147 cases) | pass | pass | pass | pass | pass | pass |
| pbkdf2-sha1 (64 cases) | pass | pass | pass | pass | pass | pass |
| pbkdf2-sha2/contract/grants | pass | pass | pass | pass | pass | pass |
| pbkdf2-sha256 (60 cases) | pass | pass | pass | pass | pass | pass |
| pbkdf2-sha384 (58 cases) | pass | pass | pass | pass | pass | pass |
| pbkdf2-sha512 (58 cases) | pass | pass | pass | pass | pass | pass |
| probe (58 cases) | pass | 1 N/A, 57 pass | 1 N/A, 54 pass, 3 xfail | 1 N/A, 57 pass | 1 N/A, 57 pass | pass |
| rsa-pss-sha256-2048-salt0 (406 cases) | pass | pass | pass | pass | pass | pass |
| rsa-pss-sha256-2048-salt32 (529 cases) | pass | pass | pass | pass | pass | pass |
| rsa-pss-sha256-3072-salt32 (421 cases) | pass | pass | pass | pass | pass | pass |
| rsa-pss-sha256-4096-salt32 (421 cases) | pass | pass | pass | pass | pass | pass |
| rsa-pss-sha384-2048-salt48 (615 cases) | pass | pass | pass | pass | pass | pass |
| rsa-pss-sha384-4096-salt48 (615 cases) | pass | pass | pass | pass | pass | pass |
| rsa-pss-sha512-4096-salt32 (835 cases) | pass | pass | pass | pass | pass | pass |
| rsa-pss-sha512-4096-salt64 (837 cases) | pass | pass | pass | pass | pass | pass |
| rsa-verify-8192/decline/importing | N/A | N/A | pass | N/A | N/A | N/A |
| rsassa-pkcs1-v15-sha256-2048 (312 cases) | pass | pass | pass | pass | pass | pass |
| rsassa-pkcs1-v15-sha256-3072 (307 cases) | pass | pass | pass | pass | pass | pass |
| rsassa-pkcs1-v15-sha256-4096 (301 cases) | pass | pass | pass | pass | pass | pass |
| rsassa-pkcs1-v15-sha256-8192 (301 cases) | pass | pass | N/A | pass | pass | pass |
| rsassa-pkcs1-v15-sha384-2048 (301 cases) | pass | pass | pass | pass | pass | pass |
| rsassa-pkcs1-v15-sha384-3072 (302 cases) | pass | pass | pass | pass | pass | pass |
| rsassa-pkcs1-v15-sha384-4096 (302 cases) | pass | pass | pass | pass | pass | pass |
| rsassa-pkcs1-v15-sha512-2048 (307 cases) | pass | pass | pass | pass | pass | pass |
| rsassa-pkcs1-v15-sha512-3072 (308 cases) | pass | pass | pass | pass | pass | pass |
| rsassa-pkcs1-v15-sha512-4096 (302 cases) | pass | pass | pass | pass | pass | pass |
| sha1-checked/decline/minting | N/A | pass | pass | pass | pass | N/A |
| sha2 (963 cases) | pass | pass | pass | pass | pass | pass |
| x25519 (1587 cases) | pass | pass | pass | pass | pass | pass |

## Failures

None.

## Expected failures

- `deltic-deno` `aes-gcm/wycheproof/tc259/bytes`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 120 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc259/straddle`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 120 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc259/whole`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 120 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc260/bytes`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 160 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc260/straddle`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 160 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc260/whole`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 160 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc263/bytes`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 120 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc263/straddle`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 120 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc263/whole`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 120 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc264/bytes`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 160 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc264/straddle`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 160 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc264/whole`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 160 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc265/bytes`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 256 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc265/straddle`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 256 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc265/whole`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 256 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc266/bytes`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 512 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc266/straddle`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 512 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc266/whole`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 512 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc267/bytes`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 1024 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc267/straddle`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 1024 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc267/whole`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 1024 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc273/bytes`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 256 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc273/straddle`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 256 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc273/whole`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 256 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc274/bytes`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 512 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc274/straddle`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 512 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc274/whole`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 512 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc275/bytes`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 1024 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc275/straddle`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 1024 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `aes-gcm/wycheproof/tc275/whole`: Deno WebCrypto: AES-GCM IV window is 96/128 bits; this case uses 1024 (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `probe/ctr-known-answers`: Deno WebCrypto: AES-CTR counter width limited to 32/64/128 bits (WIT window 1-128) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `probe/gcm-full-parameters`: Deno WebCrypto: AES-GCM decrypt refuses tags shorter than 128 bits (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `probe/gcm-nonce-window`: Deno WebCrypto: AES-GCM IV window is 96/128 bits (WIT window 12-128 bytes) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)

## Summary

- `composed`: 2 N/A, 19089 pass (19091 total)
- `deltic-browser`: 2 N/A, 19089 pass (19091 total)
- `deltic-deno`: 302 N/A, 18756 pass, 33 xfail (19091 total)
- `jco-browser`: 2 N/A, 19089 pass (19091 total)
- `jco-node`: 2 N/A, 19089 pass (19091 total)
- `wasmtime-rustcrypto`: 2 N/A, 19089 pass (19091 total)
