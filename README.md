# crypto.cr
Comprehensive cross-platform hybrid cryptographic library for Crystal supporting Ed521, X448, Anubis-GCM, Curupira1-CBC, SHA3, HMAC, HKDF, and PEM encryption.


***Fully EDGETk compliant***

#### Implements
    
1. Anubis Involutional SPN 128-bit block cipher (Barreto, ESAT/COSIC)
2. SBRC 2007: Curupira1 96-bit block cipher with 96/144/192-bit keys
3. ITI DOC-ICP-01.01 Curve E-521 Brazilian Digital Signature Standard
4. RFC 1423: Privacy Enhancement for Internet Electronic Mail
5. RFC 2104: HMAC - Keyed-Hashing for Message Authentication
6. RFC 5869: HMAC-based Key Derivation Function (HKDF)
7. RFC 7748: Curve448-Goldilocks: X448 Key Agreement Function
8. US FIPS 202 SHA-3 Permutation-Based Hash (instance of the Keccak)

## Usage
#### Import the Lib
```cr
require "crypto"
```
#### ED521 - Generate key pair
```cr
private_key = Crypto::ED521.generate_private_key
pub_x, pub_y = Crypto::ED521.get_public_key(private_key)
```
#### ED521 - Sign and verify
```cr
message = "Hello World".to_slice
signature = Crypto::ED521.sign(private_key, message)
valid = Crypto::ED521.verify(pub_x, pub_y, message, signature)
```
#### ED521 - Zero-knowledge proof
```cr
proof = Crypto::ED521.prove_knowledge(private_key)
valid_proof = Crypto::ED521.verify_knowledge(pub_x, pub_y, proof)
```
#### X448 - Key exchange
```cr
alice_priv = Crypto::X448.generate_private_key
alice_pub = Crypto::X448.get_public_key(alice_priv)
bob_priv = Crypto::X448.generate_private_key
bob_pub = Crypto::X448.get_public_key(bob_priv)
shared_alice = Crypto::X448.shared_secret(alice_priv, bob_pub)
shared_bob = Crypto::X448.shared_secret(bob_priv, alice_pub)
```
#### Anubis-GCM - Authenticated encryption
```cr
key = Random::Secure.random_bytes(32)
nonce = Random::Secure.random_bytes(12)
aead = Crypto::Anubis::AEAD.new(key)
ciphertext = aead.seal(nonce, plaintext, aad)
plaintext = aead.open(nonce, ciphertext, aad)
```
#### Curupira1-CBC - Block cipher
```cr
cipher = Crypto::Curupira1::Cipher.new(key)
cbc = Crypto::Curupira1::CBC.new(cipher, iv)
encrypted = cbc.encrypt(data)
decrypted = cbc.decrypt(encrypted)
```
#### SHA3-256 - Hash
```cr
hash = Crypto::SHA3.sha3_256(data)
```
#### HMAC-SHA3-256
```cr
mac = Crypto::HMAC.hmac(key, data)
```
#### HKDF - Key derivation
```cr
okm = Crypto::HKDF.hkdf(ikm, length, salt, info)
```
#### PEM - Encrypted key storage
```cr
pem = Crypto::PEM.ed521_private_to_pem(private_key, "password")
loaded = Crypto::PEM.parse_ed521_private_pem(pem, "password")
pub_pem = Crypto::PEM.ed521_public_to_pem(pub_x, pub_y)
pub_x, pub_y = Crypto::PEM.parse_ed521_public_pem(pub_pem)
```
#### X448 PEM
```cr
pem = Crypto::PEM.x448_private_to_pem(private_key, "password")
loaded = Crypto::PEM.parse_x448_private_pem(pem, "password")
pub_pem = Crypto::PEM.x448_public_to_pem(public_key)
pub_key = Crypto::PEM.parse_x448_public_pem(pub_pem)
```
#### Utilities
```cr
hex = Crypto.bytes_to_hex(bytes)
bytes = Crypto.hex_to_bytes(hex)
same = Crypto.constant_time_compare(a, b)
xor = Crypto.xor_bytes(a, b)
```
## CLI
#### Compile the CLI
```cr
crystal build src/crypto_cli.cr -o crypto
```
#### User Interface
```cr
Crypto Tool v1.0.0 - ALBANESE Research Lab
======================================================================
Usage: ./crypto_cli <command> [options]

Available commands:
  ed521                         E-521 curve for signatures and ZKP
  x448                          X448 curve for key exchange
  anubis                        Anubis-GCM cipher for encryption
  hmac                          Generate HMAC-SHA3-256
  hkdf                          Derive key with HKDF-SHA3-256
  hash                          Generate SHA3-256 hash of file(s)
  check                         Verify files with SHA3-256 checklist
  change-password               Change private key password

For more details, use: ./crypto_cli help <command>
```

## Contribute
**Use issues for everything**
- You can help and get help by:
  - Reporting doubts and questions
- You can contribute by:
  - Reporting issues
  - Suggesting new features or enhancements
  - Improve/fix documentation

## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2026 Pedro F. Albanese - ALBANESE Research Lab.  
Todos os direitos de propriedade intelectual sobre este software pertencem ao autor, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.
