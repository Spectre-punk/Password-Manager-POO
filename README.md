# Password Manager (POO) — Secure Single-User CLI Vault

A Java 21 command-line password manager that stores all credentials in a single
authenticated, encrypted vault file (`boveda.json`). It demonstrates three
security indicators end-to-end:

| Indicator | Primitive |
|---|---|
| **IND1** — Key encapsulation | RSA-3072 OAEP-SHA256 wrapping a random AES-256 DEK |
| **IND2** — Digital signatures | Ed25519 over the canonical vault payload |
| **IND3** — Zero-knowledge proof | Interactive Schnorr proof of knowledge over RFC 3526 Group 14 |

---

## 1. Problem definition

Users need to keep many strong, unique passwords. Writing them down or reusing
them is insecure, and cloud password managers move trust to a third party. This
project provides a **local, offline, single-user vault** whose confidentiality
and integrity depend only on a master password and standard cryptography.

The design goals are:

1. **Confidentiality at rest** — an attacker who steals `boveda.json` learns
   nothing about the stored credentials without the master password.
2. **Integrity / authenticity** — any modification of the vault is detected
   before decryption is attempted.
3. **No password-equivalent secret at rest** — the vault does not store a
   password hash; login is a zero-knowledge proof.
4. **Key separation** — the master password derives a key-encryption key (KEK),
   while a random data-encryption key (DEK) protects the credential blob.
5. **Cheap master-password rotation** — changing the master password re-encrypts
   only the small key material, not the whole credential database.

### Protected assets

| Asset | Where it lives | Protection |
|---|---|---|
| Master password | User's memory / terminal only | Never stored; used to derive KEK + ZKP secret |
| Credential passwords | `credentialsCiphertext` | AES-256-GCM under the random DEK |
| Credential metadata (service, username, notes) | Same encrypted blob | AES-256-GCM |
| KEM private key (RSA) | `kemPrivateKeyCiphertext` | AES-256-GCM under the KEK |
| Signing private key (Ed25519) | `signingPrivateKeyCiphertext` | AES-256-GCM under the KEK |
| Data-encryption key (DEK) | `encapsulatedDek` | RSA-OAEP-SHA256 under the KEM public key |
| Vault integrity | `signature` | Ed25519 over the canonical payload |
| ZKP verifier `Y` | `usuario.verifier` | Public; reveals nothing about the password |

---

## 2. Threat model and trust assumptions

### Adversaries considered

| Adversary | Capability | Mitigation |
|---|---|---|
| **Offline disk attacker** | Can read, copy, modify, replace or delete `boveda.json` | Argon2id slows guessing; Ed25519 rejects modifications; AES-GCM rejects ciphertext tampering; RSA-OAEP protects the DEK |
| **Password guesser** | Has the vault file and tries candidate passwords offline | Argon2id (64 MiB, 3 iterations) makes each guess expensive; the Schnorr verifier does not give a fast hash oracle |
| **File tamperer** | Flips bytes in the signature, ciphertext or metadata | Signature is verified **before** any decryption; mismatch raises `SecurityException` |
| **Impersonator** | Runs the Schnorr protocol without the master password | A proof produced with the wrong secret fails verification |
| **Wrong-key attacker** | Tries to unwrap the DEK with an unrelated RSA key | RSA-OAEP unwrap fails |

### Explicit trust assumptions

* **RAM during an active session is trusted.** While the vault is unlocked the
  DEK, decrypted private keys and credential passwords exist in process memory.
  An attacker who can read process memory, a debugger, a core dump, swap or a
  hibernation image is **out of scope**. `lock()` zeroizes the DEK and clears
  decrypted credentials on a best-effort basis.
* **The OS, JVM, `SecureRandom`, Bouncy Castle and Gson implementations are
  trusted.** Side-channel attacks against those libraries are out of scope.
* **The terminal is trusted.** `System.console().readPassword()` avoids echoing,
  but a keylogger or shoulder surfing is not prevented.
* **The master password has reasonable entropy.** Argon2id raises the cost of
  guessing; it cannot rescue a password such as `1234`.
* **The machine is not compromised while the vault is open.** Malware with code
  execution can read memory or keystrokes and is out of scope.

### Known limitations (not protected)

* **Vault substitution / key substitution.** The Ed25519 public key is stored
  inside the signed payload. An attacker who replaces the entire file with a
  different, self-consistent vault (different key pair) is not detected unless
  the user pins the key or verifies a fingerprint out of band. TOFU/pinning is
  future work.
* **Rollback and deletion.** An attacker can restore an older valid vault or
  delete the file (denial of service). No monotonic counter is stored.
* **Metadata leakage.** File size and ciphertext length reveal an approximate
  number/size of credentials.
* **Memory wiping is best-effort.** Java may copy arrays; `BigInteger` secrets
  cannot be zeroized; private-key destruction depends on the provider.
* **Single user, local only.** No multi-user access control, sync, recovery,
  audit log, GUI or clipboard integration.

---

## 3. Cryptographic design

### Key hierarchy

```
master password (char[])
        │
        ├── Argon2id(password, salt, 64 bytes)
        │        ├── bytes  0..31  → KEK  (AES-256)
        │        └── bytes 32..63  → Schnorr secret seed
        │                                └── x ∈ [1, q-1]  →  Y = g^x mod p
        │
        ├── KEK ──AES-256-GCM──► KEM private key (RSA)      ─┐
        │                     └► Ed25519 private key         │
        │                                                    │
        └── random DEK (32 bytes) ◄──RSA-OAEP-SHA256─────────┘
                 │
                 └──AES-256-GCM──► credentials JSON blob
```

* The first 32 bytes of the Argon2 output are the **KEK**; the last 32 bytes
  seed the **Schnorr secret**. The two uses are domain-separated.
* The **DEK is random per vault** and independent of the master password.
  Changing the master password therefore only re-encrypts the private keys and
  re-wraps the same DEK; the credentials blob is reused byte-for-byte.
* The **Ed25519 signature covers the whole payload** (metadata, encapsulated
  DEK and credentials IV/ciphertext). It is verified before any decryption.

### Primitives and parameters

| Purpose | Primitive | Parameters | Why |
|---|---|---|---|
| Password hashing / KDF | **Argon2id** (RFC 9106) | 64 MiB memory, 3 iterations, parallelism 1, 16-byte random salt, 64-byte output | Memory-hard and side-channel resistant; makes offline guessing expensive |
| Vault encryption | **AES-256-GCM** | 256-bit key, 96-bit random nonce per encryption, 128-bit tag | AEAD: confidentiality **and** integrity, no padding oracle |
| Vault authentication | **Ed25519** | 32-byte public key, 64-byte signature | Deterministic, fast, small keys, misuse-resistant |
| DEK wrapping (IND1) | **RSA-3072 OAEP** | SHA-256 digest, MGF1-SHA256, 3072-bit modulus | CCA-secure encapsulation with explicit hash pinning |
| Password proof (IND3) | **Schnorr ZKP** | RFC 3526 Group 14: 2048-bit safe prime `p`, `q = (p-1)/2`, `g = 2` | Proves knowledge of `x` without revealing the password or a password hash |
| Randomness | `SecureRandom` | JCA default | Nonces, salts, keys, challenges |

### Login and registration

**Registration**

1. Generate a 16-byte salt.
2. Derive 64 bytes with Argon2id.
3. Compute `Y = g^x mod p` from the Schnorr seed and store `Y` (public).
4. Generate RSA-3072 KEM and Ed25519 key pairs.
5. Encrypt both private keys with AES-256-GCM under the KEK.
6. Generate a random 32-byte DEK; wrap it with RSA-OAEP.
7. Sign the payload with Ed25519 and write `boveda.json`.

**Login**

1. Read `boveda.json` and verify the Ed25519 signature **before** asking for the
   password.
2. Prompt for the master password.
3. Run the three-move Schnorr proof against the stored verifier `Y`.
4. Only on success: derive the KEK, decrypt the private keys, decapsulate the
   DEK and decrypt the credential blob in memory.

### Rejected alternatives

| Rejected option | Problem | Chosen instead |
|---|---|---|
| **Raw SHA-256 / salted SHA-256** for passwords | Fast and GPU-friendly; a stolen vault enables massive offline guessing; no memory hardness | **Argon2id** |
| **PBKDF2 / bcrypt / scrypt** | Acceptable but weaker memory-hardness/side-channel profile; bcrypt truncates long passwords | **Argon2id** |
| **AES-ECB** | Deterministic, leaks plaintext patterns, provides no integrity | **AES-256-GCM** |
| **AES-CBC without a MAC** | Malleable; padding-oracle attacks | **AES-256-GCM (AEAD)** |
| **AES-GCM with a reused nonce** | Catastrophic: key/tag recovery | Fresh random 96-bit nonce per encryption |
| **RSA PKCS#1 v1.5** | Bleichenbacher / padding-oracle attacks | **RSA-OAEP-SHA256** with MGF1-SHA256 |
| **ECDSA** | Nonce reuse leaks the private key; fragile implementations | **Ed25519** (deterministic) |
| **Storing a password hash** | Password-equivalent offline target | **Schnorr verifier `Y`**; no hash is stored |
| **Plain JSON / Base64** | No confidentiality or integrity | AES-GCM + Ed25519 |

---

## 4. Vault file format

`boveda.json` is UTF-8 JSON (abridged):

```json
{
  "payload": {
    "usuario": {
      "salt": "<base64 16 bytes>",
      "verifier": "<base64 Y>",
      "kemPublicKey": "<base64 X.509 RSA>",
      "kemPrivateKeyIv": "<base64 12 bytes>",
      "kemPrivateKeyCiphertext": "<base64 AES-GCM>",
      "signingPublicKey": "<base64 X.509 Ed25519>",
      "signingPrivateKeyIv": "<base64 12 bytes>",
      "signingPrivateKeyCiphertext": "<base64 AES-GCM>",
      "nombreDeUsuario": "alice"
    },
    "encapsulatedDek": "<base64 RSA-OAEP>",
    "credentialsIv": "<base64 12 bytes>",
    "credentialsCiphertext": "<base64 AES-GCM>"
  },
  "signature": "<base64 Ed25519 over the canonical payload>"
}
```

Credential passwords are held as `char[]` in memory and serialized as numeric
UTF-16 code units inside the encrypted blob — never as a JSON string. The file
is written atomically (temporary file + rename) with owner-only permissions on
POSIX systems.

---

## 5. Build and run

### Prerequisites

* JDK **21** or newer (`java -version`)
* Maven **3.9+** (`mvn -version`)

### Run the test suite

```bash
mvn clean test
```

Expected: **63 tests, 0 failures, 0 errors**.

### Run the CLI

```bash
mvn exec:java
```

The default main class is `cli.Main`. Optional vault path:

```bash
mvn exec:java -Dexec.args="/path/to/boveda.json"
```

On first run the CLI asks for a username and a master password (twice), creates
`boveda.json`, and opens the menu:

```
1. Add credential
2. List credentials
3. View credential details
4. Change master password
5. Save, wipe memory and exit
0. Exit without saving
```

> **Secure input note.** `System.console().readPassword()` masks input when a
> real terminal console is available. When no console is attached (IDE run
> configurations, pipes, or Maven's in-process `exec:java`), the CLI falls back
> to a line-based `Scanner` and the input may be echoed. For day-to-day use,
> run from a terminal or an IDE console.

### Build a jar

```bash
mvn clean package
```

The jar is not a fat jar; dependencies must be on the classpath. The manifest
main class is `cli.Main`.

---

## 6. Micro-evidence programs

Three independent `main` classes under `src/main/java/evidencias/` demonstrate
IND1, IND2 and IND3 in isolation. Each prints inputs, cryptographic outputs and
explicit `PASS`/`FAIL` lines, and ends with `[RESULT] PASS`.

```bash
mvn exec:java -Dexec.mainClass=evidencias.EvidenciaKEM
mvn exec:java -Dexec.mainClass=evidencias.EvidenciaFirma
mvn exec:java -Dexec.mainClass=evidencias.EvidenciaZKP
```

The printed output is **reproducible**: fixed demo DEK/password/salt and the
RFC 8032 Ed25519 test vector are used, and randomized values are not printed.

### IND1 — KEM

```
============================================================
 IND1 - KEM (RSA-OAEP-SHA256)
============================================================
[INPUT]  DEK (32 bytes): 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
[INPUT]  DEK SHA-256:    630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd
[OUTPUT] KEM key pair: RSA / 3072-bit modulus
[OUTPUT] OAEP: SHA-256 digest, MGF1-SHA256
[OUTPUT] Encapsulated DEK length: 384 bytes (OAEP randomness makes the bytes differ per run)
[OUTPUT] Recovered DEK: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
[VERIFY] Recovered DEK equals input DEK: PASS
[VERIFY] Tampered encapsulation rejected: PASS
[VERIFY] Unrelated private key rejected: PASS

[RESULT] PASS
```

### IND2 — Ed25519

```
============================================================
 IND2 - Digital Signature (Ed25519)
============================================================
[INPUT]  RFC 8032 TEST 1 seed (32 bytes): 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
[OUTPUT] Derived public key (32 bytes): d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
[VERIFY] Derived public key matches RFC 8032: PASS
[OUTPUT] RFC 8032 signature (empty message): e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
[VERIFY] Signature matches RFC 8032 vector: PASS
[INPUT]  Message: boveda.json|usuario=alice|credenciales=2
[OUTPUT] Signature (64 bytes): 4893009a53525f04ba9d48730a87948d1485cf2a19effbde6397012fb18fdeb6cae380c2553eca4bf466f0e0c8f736152de5219d179c625f3a9d57974572540e
[OUTPUT] Signature SHA-256: 1555bec5454012269cf8b8775e69b7b7a211bb891487411f5513fea83eea2e20
[VERIFY] Valid signature accepted: PASS
[VERIFY] One-byte signature tampering rejected: PASS
[VERIFY] Different message rejected: PASS

[RESULT] PASS
```

### IND3 — Schnorr ZKP

```
============================================================
 IND3 - Schnorr Zero-Knowledge Proof (IND3)
============================================================
[INPUT]  Group: RFC 3526 Group 14 (p 2048 bits, q 2047 bits, g=2)
[INPUT]  Password (fixed demo value): "demo-master-password"
[INPUT]  Salt (16 bytes): 000102030405060708090a0b0c0d0e0f
[OUTPUT] Secret x SHA-256:   dbb2b83a1afd8f8c1483a40769b764e92251e18b81c93a781965c847f5f09625
[OUTPUT] Verifier Y SHA-256: e30c429a900b63a2ad1bc39f88f7fc7bb60a6622f377ffa6bf8aaaadaacc9c5a
[VERIFY] Verifier is in the order-q subgroup: PASS
[VERIFY] Registration is deterministic: PASS
[OUTPUT] Commitment R, challenge c and response s generated (random nonce; values vary per run)
[VERIFY] Valid proof accepted: PASS
[VERIFY] Impersonation with wrong password rejected: PASS
[VERIFY] Tampered response rejected: PASS

[RESULT] PASS
```

---

## 7. Automated tests

`mvn clean test` runs **63 JUnit 5 tests**:

| Package | Focus |
|---|---|
| `crypto` | Argon2id vectors/parameters, AES-GCM round-trip and tamper/wrong-key rejection, RSA-OAEP KEM, Ed25519 sign/verify, Schnorr proof and impersonation rejection |
| `model` | `Credential` secret handling, `UsuarioMaestro` registration/ZKP/unlock, `Gestor` session lifecycle, DEK zeroization and master-password rotation |
| `storage` | Save/reload round-trip, tampered-signature abort, verify-before-decrypt, wrong-DEK AEAD failure |
| `security` | Full end-to-end lifecycle (all five primitives + rotation) and abuse scenarios: one-byte file tampering, one-byte AES-GCM tampering (`AEADBadTagException`), ZKP impersonation, unrelated KEM private key |
| `cli` | Scripted registration/login/menu sessions across restarts, wrong-password lockout, password rotation through the menu |
| `util` | Secure password generator |

---

## 8. Project structure

```
src/main/java/
  cli/          Main (interactive CLI), PasswordManagerApp (provider bootstrap)
  crypto/       Argon2KDF, VaultCipher, KeyEncapsulator, DigitalSigner, SchnorrZKP
  model/        Credential, Usuario, UsuarioMaestro, Gestor
  storage/      VaultFile (DTO), PersistenciaBoveda (save/load/verify/rewrap)
  util/         SecretWiper, GeneradorDeContraseñas
  evidencias/   EvidenciaKEM, EvidenciaFirma, EvidenciaZKP
src/test/java/  crypto, model, storage, security, cli, util
pom.xml
```

---

## 9. Licensing and legal considerations

| Component | License |
|---|---|
| **Bouncy Castle** (`bcprov-jdk18on`) | MIT-style permissive license |
| **Gson** (`com.google.code.gson:gson`) | Apache License 2.0 |
| **JUnit Jupiter** | Eclipse Public License 2.0 |
| **Apache Maven plugins** | Apache License 2.0 |

If you redistribute this project or a binary that bundles these dependencies:

* Keep the Bouncy Castle copyright/license notice and attribution.
* Keep the Gson `LICENSE`/`NOTICE` files as required by Apache 2.0.
* Add a `LICENSE` file for this project. It is academic coursework; if you want
  to publish it, an **MIT** license is a compatible, simple choice.
* The project uses standard, publicly documented cryptography (Argon2id,
  AES-GCM, Ed25519, RSA-OAEP, Schnorr). Cryptographic export/import rules vary
  by jurisdiction; verify local regulations before distributing binaries.

---

## 10. Status

Phases 1–6 complete:

1. Maven/Java 21 scaffolding and Bouncy Castle provider.
2. Cryptographic primitives with tests.
3. Domain model and authenticated JSON persistence.
4. Interactive CLI, registration/login, credential management, password rotation.
5. End-to-end and abuse-scenario tests.
6. Standalone evidence programs and this report.

**Not production-ready.** It is a teaching/academic implementation: no key
pinning, no rollback protection, no memory encryption, and no multi-user or
recovery features.
