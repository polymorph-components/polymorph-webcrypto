# Test matrix

| Case | deltic-deno | jco-browser | jco-node | wasmtime-rustcrypto |
| --- | --- | --- | --- | --- |
| probe (16 cases) | pass | 7 N/A, 9 pass | pass | pass |
| rsa-oaep-decrypt/decline/minting | N/A | pass | N/A | N/A |
| rsa-oaep-sha256-2048 (80 cases) | 70 pass, 10 xfail | N/A | pass | pass |
| rsa-oaep-sha256-2688 (16 cases) | xfail | N/A | pass | pass |
| rsa-oaep-sha256-3072 (80 cases) | 70 pass, 10 xfail | N/A | pass | pass |
| rsa-oaep-sha256-4032 (12 cases) | xfail | N/A | pass | pass |
| rsa-oaep-sha256-4096 (80 cases) | 70 pass, 10 xfail | N/A | pass | pass |
| rsa-oaep-sha256-8192 (6 cases) | pass | N/A | pass | pass |
| rsa-oaep-sha384-2048 (74 cases) | 68 pass, 6 xfail | N/A | pass | pass |
| rsa-oaep-sha384-3072 (6 cases) | pass | N/A | pass | pass |
| rsa-oaep-sha384-3104 (6 cases) | xfail | N/A | pass | pass |
| rsa-oaep-sha384-4096 (6 cases) | pass | N/A | pass | pass |
| rsa-oaep-sha384-8192 (6 cases) | pass | N/A | pass | pass |
| rsa-oaep-sha512-2048 (72 cases) | 70 pass, 2 xfail | N/A | pass | pass |
| rsa-oaep-sha512-3072 (72 cases) | 68 pass, 4 xfail | N/A | pass | pass |
| rsa-oaep-sha512-4096 (78 cases) | 70 pass, 8 xfail | N/A | pass | pass |
| rsa-oaep-sha512-8192 (6 cases) | pass | N/A | pass | pass |
| rsa-sign/decline/minting | N/A | pass | N/A | N/A |
| rsassa-pkcs1-v15-sha256-2048 (20 cases) | pass | N/A | pass | pass |
| rsassa-pkcs1-v15-sha256-3072 (18 cases) | pass | N/A | pass | pass |
| rsassa-pkcs1-v15-sha256-4096 (16 cases) | pass | N/A | pass | pass |
| rsassa-pkcs1-v15-sha384-2048 (16 cases) | pass | N/A | pass | pass |
| rsassa-pkcs1-v15-sha384-3072 (16 cases) | pass | N/A | pass | pass |
| rsassa-pkcs1-v15-sha384-4096 (16 cases) | pass | N/A | pass | pass |
| rsassa-pkcs1-v15-sha512-2048 (18 cases) | pass | N/A | pass | pass |
| rsassa-pkcs1-v15-sha512-3072 (18 cases) | pass | N/A | pass | pass |
| rsassa-pkcs1-v15-sha512-4096 (16 cases) | pass | N/A | pass | pass |

## Failures

None.

## Expected failures

- `deltic-deno` `rsa-oaep-sha256-2048/wycheproof/tc33-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2048/wycheproof/tc33-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2048/wycheproof/tc34-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2048/wycheproof/tc34-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2048/wycheproof/tc35-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2048/wycheproof/tc35-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2048/wycheproof/tc36-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2048/wycheproof/tc36-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2048/wycheproof/tc37-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2048/wycheproof/tc37-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc377-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc377-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc378-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc378-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc379-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc379-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc380-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc380-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc381-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc381-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc382-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc382-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc383-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc383-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc384-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-2688/wycheproof-misc/tc384-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (2688-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-3072/wycheproof/tc33-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-3072/wycheproof/tc33-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-3072/wycheproof/tc34-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-3072/wycheproof/tc34-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-3072/wycheproof/tc35-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-3072/wycheproof/tc35-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-3072/wycheproof/tc36-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-3072/wycheproof/tc36-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-3072/wycheproof/tc37-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-3072/wycheproof/tc37-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4032/wycheproof-misc/tc386-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (4032-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4032/wycheproof-misc/tc386-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (4032-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4032/wycheproof-misc/tc387-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (4032-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4032/wycheproof-misc/tc387-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (4032-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4032/wycheproof-misc/tc388-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (4032-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4032/wycheproof-misc/tc388-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (4032-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4032/wycheproof-misc/tc389-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (4032-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4032/wycheproof-misc/tc389-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (4032-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4032/wycheproof-misc/tc390-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (4032-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4032/wycheproof-misc/tc390-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (4032-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4032/wycheproof-misc/tc391-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (4032-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4032/wycheproof-misc/tc391-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (4032-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4096/wycheproof/tc33-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4096/wycheproof/tc33-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4096/wycheproof/tc34-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4096/wycheproof/tc34-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4096/wycheproof/tc35-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4096/wycheproof/tc35-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4096/wycheproof/tc36-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4096/wycheproof/tc36-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4096/wycheproof/tc37-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha256-4096/wycheproof/tc37-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha384-2048/wycheproof/tc32-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha384-2048/wycheproof/tc32-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha384-2048/wycheproof/tc33-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha384-2048/wycheproof/tc33-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha384-2048/wycheproof/tc34-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha384-2048/wycheproof/tc34-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha384-3104/wycheproof-misc/tc393-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (3104-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha384-3104/wycheproof-misc/tc393-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (3104-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha384-3104/wycheproof-misc/tc394-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (3104-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha384-3104/wycheproof-misc/tc394-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (3104-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha384-3104/wycheproof-misc/tc395-jwk`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (3104-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha384-3104/wycheproof-misc/tc395-pkcs8`: Deno WebCrypto: RSA-OAEP unusable at non-standard modulus size (3104-bit) (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha512-2048/wycheproof/tc33-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha512-2048/wycheproof/tc33-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha512-3072/wycheproof/tc32-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha512-3072/wycheproof/tc32-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha512-3072/wycheproof/tc33-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha512-3072/wycheproof/tc33-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha512-4096/wycheproof/tc33-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha512-4096/wycheproof/tc33-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha512-4096/wycheproof/tc34-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha512-4096/wycheproof/tc34-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha512-4096/wycheproof/tc35-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha512-4096/wycheproof/tc35-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha512-4096/wycheproof/tc36-jwk`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)
- `deltic-deno` `rsa-oaep-sha512-4096/wycheproof/tc36-pkcs8`: Deno WebCrypto: valid Constructed+EncryptionWithLabel OAEP ciphertext refused (OperationError); plain-label vectors decrypt fine (https://github.com/polymorph-components/polymorph-webcrypto/issues/351)

## Summary

- `deltic-deno`: 2 N/A, 686 pass, 84 xfail (772 total)
- `jco-browser`: 761 N/A, 11 pass (772 total)
- `jco-node`: 2 N/A, 770 pass (772 total)
- `wasmtime-rustcrypto`: 2 N/A, 770 pass (772 total)
