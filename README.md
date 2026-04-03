# crypto.cr
Comprehensive cryptographic library for Crystal supporting ED521, X448, Anubis-GCM, Curupira1-CBC, SHA3, HMAC, HKDF, and PEM encryption.

require "crypto"

## Usage
### ED521 - Generate key pair
```
private_key = Crypto::ED521.generate_private_key
pub_x, pub_y = Crypto::ED521.get_public_key(private_key)
```
### ED521 - Sign and verify
```
message = "Hello World".to_slice
signature = Crypto::ED521.sign(private_key, message)
valid = Crypto::ED521.verify(pub_x, pub_y, message, signature)
```
### ED521 - Zero-knowledge proof
```
proof = Crypto::ED521.prove_knowledge(private_key)
valid_proof = Crypto::ED521.verify_knowledge(pub_x, pub_y, proof)
```
### X448 - Key exchange
```
alice_priv = Crypto::X448.generate_private_key
alice_pub = Crypto::X448.get_public_key(alice_priv)
bob_priv = Crypto::X448.generate_private_key
bob_pub = Crypto::X448.get_public_key(bob_priv)
shared_alice = Crypto::X448.shared_secret(alice_priv, bob_pub)
shared_bob = Crypto::X448.shared_secret(bob_priv, alice_pub)
```
### Anubis-GCM - Authenticated encryption
```
key = Random::Secure.random_bytes(32)
nonce = Random::Secure.random_bytes(12)
aead = Crypto::Anubis::AEAD.new(key)
ciphertext = aead.seal(nonce, plaintext, aad)
plaintext = aead.open(nonce, ciphertext, aad)
```
### Curupira1-CBC - Block cipher
```
cipher = Crypto::Curupira1::Cipher.new(key)
cbc = Crypto::Curupira1::CBC.new(cipher, iv)
encrypted = cbc.encrypt(data)
decrypted = cbc.decrypt(encrypted)
```
### SHA3-256 - Hash
```
hash = Crypto::SHA3.sha3_256(data)
```
### HMAC-SHA3-256
```
mac = Crypto::HMAC.hmac(key, data)
```
### HKDF - Key derivation
```
okm = Crypto::HKDF.hkdf(ikm, length, salt, info)
```
### PEM - Encrypted key storage
```
pem = Crypto::PEM.ed521_private_to_pem(private_key, "password")
loaded = Crypto::PEM.parse_ed521_private_pem(pem, "password")
pub_pem = Crypto::PEM.ed521_public_to_pem(pub_x, pub_y)
pub_x, pub_y = Crypto::PEM.parse_ed521_public_pem(pub_pem)
```
### X448 PEM
```
pem = Crypto::PEM.x448_private_to_pem(private_key, "password")
loaded = Crypto::PEM.parse_x448_private_pem(pem, "password")
pub_pem = Crypto::PEM.x448_public_to_pem(public_key)
pub_key = Crypto::PEM.parse_x448_public_pem(pub_pem)
```
### Utilities
```
hex = Crypto.bytes_to_hex(bytes)
bytes = Crypto.hex_to_bytes(hex)
same = Crypto.constant_time_compare(a, b)
xor = Crypto.xor_bytes(a, b)
```
## Compile the CLI
```
crystal build src/crypto_cli.cr -o crypto
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
