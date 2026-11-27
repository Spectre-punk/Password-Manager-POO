# Password Manager (POO) — Secure Single-User CLI Vault

A local, offline, single-user password manager written in **Java 21**. It keeps
all of your credentials in one authenticated, encrypted file (`boveda.json`) and
is operated entirely from the terminal. There is no server, no cloud account and
no telemetry: the confidentiality and integrity of the vault depend only on your
master password and standard cryptography.

The project was built as an academic exercise in object-oriented programming and
applied cryptography. It demonstrates three security indicators end-to-end:

| Indicator | Primitive |
|---|---|
| **IND1** — Key encapsulation | RSA-3072 OAEP-SHA256 wrapping a random AES-256 DEK |
| **IND2** — Digital signatures | Ed25519 over the canonical vault payload |
| **IND3** — Zero-knowledge proof | Interactive Schnorr proof of knowledge over RFC 3526 Group 14 |

---

## 1. What this project does

In plain terms:

1. **You create a vault once.** On first launch you choose a username and a
   master password. The program generates all the cryptographic material it
   needs and writes `boveda.json`.
2. **You unlock the vault with your master password.** The program verifies the
   file's signature first, then proves that you know the master password using a
   zero-knowledge proof. A wrong password is rejected; the password itself is
   never stored.
3. **You manage credentials.** From a text menu you can add a credential (service,
   username, notes, password), list the stored entries without revealing
   passwords, or view one entry's full details.
4. **You save and exit.** Saving re-encrypts the credential list, signs the
   payload and writes the file atomically; exiting wipes the session key and
   decrypted credentials from memory.
5. **You can change the master password.** The program re-encrypts only the small
   private-key material and re-wraps the data key. The (potentially large)
   credentials blob is **not** re-encrypted.

Everything is stored locally in a single JSON file. Losing the file means losing
the vault; losing the master password means the vault cannot be recovered. That
is the intended trade-off for a local, offline manager.

### Feature summary

| Feature | Behaviour |
|---|---|
| First-run registration | Username + master password (with confirmation) creates a new vault |
| Signature-first login | Ed25519 signature is verified **before** the password is requested |
| Password authentication | Three-move Schnorr proof; no password hash is stored |
| Add credential | Service, username, notes, optional generated password |
| List credentials | Shows service, username and notes; never the password |
| View credential | Shows full details for one selected entry, including its password |
| Password generator | `SecureRandom`, 15 characters plus `-` separators |
| Master-password rotation | Re-encrypts private keys and re-wraps the DEK, keeps the credentials blob |
| Secure input | `System.console().readPassword()` with a `Scanner` fallback |
| Atomic persistence | Temporary file + atomic rename, owner-only permissions on POSIX |
| Memory hygiene | Secrets held as `char[]`/`byte[]`, wiped on lock/exit where possible |
| Standalone evidence | Three executable classes for IND1, IND2 and IND3 |
| Automated tests | 63 JUnit 5 tests, including abuse scenarios |

---

## 2. Quick start

### Prerequisites

* JDK **21** or newer (`java -version`)
* Maven **3.9+** (`mvn -version`)

### Run the tests

```bash
mvn clean test
```

Expected: **63 tests, 0 failures, 0 errors**.

### Run the application

```bash
mvn exec:java
```

`cli.Main` is the default main class. To use a specific vault path:

```bash
mvn exec:java -Dexec.args="/path/to/boveda.json"
```

On first run the program asks for a username and a master password (twice) and
creates `boveda.json` in the current directory (or at the given path). On later
runs it asks only for the master password and opens the menu.

### Build a jar

```bash
mvn clean package
```

The resulting jar is **not** a fat jar: dependencies must be on the classpath.
The manifest main class is `cli.Main`.

> **Secure input note.** `System.console().readPassword()` masks input when a
> real terminal console is attached. When no console is available (some IDE run
> configurations, pipes, or Maven's in-process `exec:java`), the program falls
> back to a line-based `Scanner` and the input may be echoed. For daily use, run
> from a terminal or an IDE console.

---

## 3. How to use it

### 3.1 First run (registration)

```
No vault found. First-run registration.
Username: alice
Master password: ********
Confirm master password: ********
Vault created: /home/alice/boveda.json
```

The program generates a random salt, derives the master key with Argon2id,
computes the Schnorr verifier, creates the RSA and Ed25519 key pairs, encrypts
the private keys, generates a random data key, signs the payload and writes the
vault.

### 3.2 Later runs (login)

```
Master password: ********
Vault unlocked.
```

The signature is checked before the password prompt. A wrong password is
rejected; after three failed attempts the program exits with a security error.

### 3.3 Main menu

```
=== Password Manager ===
1. Add credential
2. List credentials
3. View credential details
4. Change master password
5. Save, wipe memory and exit
0. Exit without saving
Option:
```

#### Option 1 — Add credential

The prompts are, in order:

```
Service: github
Username/email: alice
Notes: work account
Generate a password? (y/N): n
Password: ********
Credential added and saved.
```

If you answer `y`, the program generates a password, prints it so you can copy
it, and stores it without asking you to type one. Each added credential is saved
immediately, so unsaved changes cannot be lost.

#### Option 2 — List credentials

```
1. github | alice | work account
2. mail   | alice@example.com | personal
```

Only metadata is shown; stored passwords are never printed by the list command.

#### Option 3 — View credential

Select an entry by number to print its service, username, notes and password.
The password is copied into a temporary `char[]`, printed, and then wiped.

#### Option 4 — Change master password

```
Current master password: ********
New master password: ********
Confirm new master password: ********
Master password changed and vault saved.
```

The current password is checked with the ZKP. The private keys are re-encrypted
under a new KEK derived from the new password, a new salt and verifier are
generated, and the DEK is re-wrapped. The encrypted credentials blob is reused
byte-for-byte, so rotation does not touch the credential data. The old password
stops working immediately.

#### Option 5 / 0 — Exit

* `5` saves the current state, wipes the session key and exits.
* `0` exits without saving (useful for a read-only session).

### 3.4 Example end-to-end session

```text
$ mvn exec:java -Dexec.args="demo/boveda.json"

No vault found. First-run registration.
Username: alice
Master password: ********
Confirm master password: ********
Vault created: /home/alice/demo/boveda.json

=== Password Manager ===
1. Add credential
2. List credentials
3. View credential details
4. Change master password
5. Save, wipe memory and exit
0. Exit without saving
Option: 1
Service: github
Username/email: alice
Notes: work account
Generate a password? (y/N): n
Password: ********
Credential added and saved.

=== Password Manager ===
...
Option: 5
Saved. Exiting.

$ mvn exec:java -Dexec.args="demo/boveda.json"
Master password: ********
Vault unlocked.

=== Password Manager ===
...
Option: 2
1. github | alice | work account

=== Password Manager ===
...
Option: 0
Exiting without saving.
```

---

## 4. How it works

### 4.1 Session lifecycle

```
lock ──register/login──► unlocked ──menu operations──► save ──► locked
                              │
                              └── exit / error ──► wipe DEK, keys, credentials
```

* While locked, no DEK, private key or decrypted credential is kept.
* While unlocked, the DEK and decrypted data live in process memory. This is the
  trusted-RAM window described in the threat model.
* `Gestor.lock()` zeroizes the DEK buffer, clears credential passwords and drops
  private-key references.

### 4.2 Data flow

```
master password (char[])
        │
        ├── Argon2id(password, salt, 64 bytes)
        │        ├── bytes  0..31  → KEK (AES-256)
        │        └── bytes 32..63  → Schnorr secret seed
        │                                └── x ∈ [1, q-1]  →  Y = g^x mod p
        │
        ├── KEK ──AES-256-GCM──► RSA private key
        │                     └► Ed25519 private key
        │
        └── random DEK (32 bytes) ◄──RSA-OAEP-SHA256── KEM public key
                 │
                 └──AES-256-GCM──► credentials JSON blob
```

### 4.3 Registration

1. Generate a 16-byte random salt.
2. Derive 64 bytes with Argon2id.
3. Use the first 32 bytes as the KEK and the last 32 bytes as the Schnorr seed.
4. Compute the verifier `Y = g^x mod p` and store it (public).
5. Generate an RSA-3072 KEM key pair and an Ed25519 signing key pair.
6. Encrypt both private keys with AES-256-GCM under the KEK.
7. Generate a random 32-byte DEK and wrap it with RSA-OAEP under the KEM public
   key.
8. Sign the canonical payload with Ed25519 and write the vault atomically.

### 4.4 Login

1. Read `boveda.json`.
2. Verify the Ed25519 signature **before** asking for the password. A mismatch
   raises `SecurityException` immediately.
3. Prompt for the master password.
4. Run the three-move Schnorr proof against the stored verifier:
   * prover sends commitment `R = g^r mod p`,
   * verifier sends a random challenge `c`,
   * prover sends `s = (r + c·x) mod q`,
   * verifier checks `g^s ≡ R·Y^c (mod p)`.
5. Only on success: derive the KEK, decrypt the private keys, decapsulate the
   DEK, decrypt the credential blob and keep it in memory.

### 4.5 Saving

1. Serialize the credential list to JSON (passwords as numeric UTF-16 code
   units, never as strings).
2. Encrypt the JSON with AES-256-GCM under the DEK (fresh 96-bit nonce).
3. Wrap the DEK with RSA-OAEP under the KEM public key.
4. Build the payload and sign its canonical JSON with Ed25519.
5. Write to a temporary file, then atomically move it over `boveda.json`.

### 4.6 Master-password rotation

1. Re-derive the KEK and Schnorr seed from the new password with a fresh salt.
2. Re-encrypt the existing RSA and Ed25519 private keys under the new KEK.
3. Recompute the verifier `Y`.
4. Re-wrap the same DEK under the unchanged KEM public key.
5. Re-sign the payload.
6. Keep the existing `credentialsIv` and `credentialsCiphertext` unchanged.

---

## 5. Architecture

### 5.1 Packages and responsibilities

| Package / class | Responsibility |
|---|---|
| `cli.Main` | Interactive menu, secure input, registration/login flows, password rotation |
| `cli.PasswordManagerApp` | Registers the Bouncy Castle provider |
| `crypto.Argon2KDF` | Argon2id key derivation (64 MiB, 3 iterations, 16-byte salt) |
| `crypto.VaultCipher` | AES-256-GCM encryption/decryption with fresh nonces |
| `crypto.KeyEncapsulator` | RSA-3072 OAEP-SHA256 DEK encapsulation (IND1) |
| `crypto.DigitalSigner` | Ed25519 key generation, signing and verification (IND2) |
| `crypto.SchnorrZKP` | Schnorr registration and interactive proof (IND3) |
| `model.Credential` | Plain credential POJO with a `char[]` password |
| `model.Usuario` | Base user type holding public identity data |
| `model.UsuarioMaestro` | Salt, verifier, public keys, KEK-encrypted private keys, rotation |
| `model.Gestor` | Singleton session manager: unlock, save, lock, password rotation |
| `storage.VaultFile` | Gson DTO for the on-disk payload and signature |
| `storage.PersistenciaBoveda` | Save/load, signature verification, decryption, re-wrap |
| `util.SecretWiper` | Best-effort zeroization of `byte[]`, `char[]` and keys |
| `util.GeneradorDeContraseñas` | `SecureRandom` password generator |
| `evidencias.*` | Standalone IND1/IND2/IND3 demonstration programs |

### 5.2 Key hierarchy

* **Master password** → Argon2id → **KEK** + **Schnorr seed**.
* **KEK** → AES-256-GCM → RSA and Ed25519 private keys.
* **Random DEK** → AES-256-GCM → credentials blob.
* **DEK** → RSA-OAEP-SHA256 → `encapsulatedDek`.
* **Schnorr seed** → `x` → `Y = g^x mod p` (public verifier).

The DEK is independent of the master password. That is what makes rotation cheap:
the password-derived material changes, but the DEK and the credentials blob do
not.

---

## 6. Vault file format

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
UTF-16 code units inside the encrypted blob — never as a JSON string. The file is
written atomically (temporary file + rename) with owner-only permissions on POSIX
systems.

---

## 7. Security design

### 7.1 Protected assets

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

### 7.2 Threat model and trust assumptions

| Adversary | Capability | Mitigation |
|---|---|---|
| **Offline disk attacker** | Can read, copy, modify, replace or delete `boveda.json` | Argon2id slows guessing; Ed25519 rejects modifications; AES-GCM rejects ciphertext tampering; RSA-OAEP protects the DEK |
| **Password guesser** | Has the vault file and tries candidate passwords offline | Argon2id (64 MiB, 3 iterations) makes each guess expensive; the Schnorr verifier is not a fast hash oracle |
| **File tamperer** | Flips bytes in the signature, ciphertext or metadata | Signature is verified **before** any decryption; mismatch raises `SecurityException` |
| **Impersonator** | Runs the Schnorr protocol without the master password | A proof produced with the wrong secret fails verification |
| **Wrong-key attacker** | Tries to unwrap the DEK with an unrelated RSA key | RSA-OAEP unwrap fails |

**Explicit trust assumptions**

* **RAM during an active session is trusted.** While unlocked, the DEK, private
  keys and decrypted credentials exist in process memory. Memory scraping,
  debuggers, core dumps, swap and hibernation are out of scope. `lock()` wipes
  secrets on a best-effort basis.
* **The OS, JVM, `SecureRandom`, Bouncy Castle and Gson are trusted.** Attacks
  against those implementations are out of scope.
* **The terminal is trusted.** `readPassword()` avoids echoing, but keyloggers
  and shoulder surfing are not prevented.
* **The master password has reasonable entropy.** Argon2id raises the cost of
  guessing; it cannot rescue a trivial password.
* **The machine is not compromised while the vault is open.** Malware with code
  execution can read memory or keystrokes.

### 7.3 Cryptographic choices

| Purpose | Primitive | Parameters | Why |
|---|---|---|---|
| Password hashing / KDF | **Argon2id** (RFC 9106) | 64 MiB, 3 iterations, parallelism 1, 16-byte salt, 64-byte output | Memory-hard, side-channel resistant; expensive offline guessing |
| Vault encryption | **AES-256-GCM** | 256-bit key, 96-bit random nonce, 128-bit tag | AEAD: confidentiality **and** integrity; no padding oracle |
| Vault authentication | **Ed25519** | 32-byte public key, 64-byte signature | Deterministic, fast, small, misuse-resistant |
| DEK wrapping (IND1) | **RSA-3072 OAEP** | SHA-256 + MGF1-SHA256 | CCA-secure encapsulation with explicit hash pinning |
| Password proof (IND3) | **Schnorr ZKP** | RFC 3526 Group 14: 2048-bit `p`, `q = (p-1)/2`, `g = 2` | Proves knowledge of `x` without revealing the password or a password hash |
| Randomness | `SecureRandom` | JCA default | Salts, nonces, keys, challenges |

### 7.4 Rejected alternatives

| Rejected option | Problem | Chosen instead |
|---|---|---|
| **Raw SHA-256 / salted SHA-256** for passwords | Fast and GPU-friendly; a stolen vault enables massive offline guessing | **Argon2id** |
| **PBKDF2 / bcrypt / scrypt** | Weaker memory-hardness/side-channel profile; bcrypt truncates long passwords | **Argon2id** |
| **AES-ECB** | Deterministic, leaks plaintext patterns, no integrity | **AES-256-GCM** |
| **AES-CBC without a MAC** | Malleable; padding-oracle attacks | **AES-256-GCM (AEAD)** |
| **AES-GCM with a reused nonce** | Catastrophic key/tag recovery | Fresh random 96-bit nonce per encryption |
| **RSA PKCS#1 v1.5** | Bleichenbacher / padding-oracle attacks | **RSA-OAEP-SHA256** |
| **ECDSA** | Nonce reuse leaks the private key; fragile implementations | **Ed25519** (deterministic) |
| **Storing a password hash** | Password-equivalent offline target | **Schnorr verifier `Y`**; no hash stored |
| **Plain JSON / Base64** | No confidentiality or integrity | AES-GCM + Ed25519 |

### 7.5 Known limitations

* **Vault substitution / key substitution.** The Ed25519 public key is stored
  inside the signed payload. An attacker who replaces the entire file with a
  different, self-consistent vault is not detected unless the key is pinned or a
  fingerprint is verified out of band. TOFU/pinning is future work.
* **Rollback and deletion.** An older valid vault can be restored, or the file
  deleted (denial of service). No monotonic counter is stored.
* **Metadata leakage.** File size and ciphertext length reveal an approximate
  number/size of credentials.
* **Memory wiping is best-effort.** Java may copy arrays; `BigInteger` secrets
  cannot be zeroized; private-key destruction depends on the provider.
* **Single user, local only.** No multi-user access control, sync, recovery,
  audit log, GUI or clipboard integration.
* **Not production-ready.** This is a teaching/academic implementation.

---

## 8. Micro-evidence programs

Three independent `main` classes under `src/main/java/evidencias/` demonstrate
IND1, IND2 and IND3 in isolation. Each prints inputs, cryptographic outputs and
explicit `PASS`/`FAIL` lines, and ends with `[RESULT] PASS`.

```bash
mvn exec:java -Dexec.mainClass=evidencias.EvidenciaKEM
mvn exec:java -Dexec.mainClass=evidencias.EvidenciaFirma
mvn exec:java -Dexec.mainClass=evidencias.EvidenciaZKP
```

The output is **reproducible**: fixed demo DEK/password/salt and the RFC 8032
Ed25519 test vector are used, and randomized values are not printed.

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

## 9. Automated tests

`mvn clean test` runs **63 JUnit 5 tests**:

| Package | Focus |
|---|---|
| `crypto` | Argon2id vectors/parameters, AES-GCM round-trip and tamper/wrong-key rejection, RSA-OAEP KEM, Ed25519 sign/verify, Schnorr proof and impersonation rejection |
| `model` | `Credential` secret handling, `UsuarioMaestro` registration/ZKP/unlock, `Gestor` session lifecycle, DEK zeroization and master-password rotation |
| `storage` | Save/reload round-trip, tampered-signature abort, verify-before-decrypt, wrong-DEK AEAD failure |
| `security` | Full end-to-end lifecycle (all five primitives + rotation) and abuse scenarios: one-byte file tampering, one-byte AES-GCM tampering (`AEADBadTagException`), ZKP impersonation, unrelated KEM private key |
| `cli` | Scripted registration/login/menu sessions across restarts, wrong-password lockout, password rotation through the menu |
| `util` | Secure password generator |

Notable negative tests:

* flip one byte of the Ed25519 signature → `SecurityException` before decryption;
* flip one byte of the AES-GCM ciphertext → `AEADBadTagException`;
* authenticate with a wrong password → proof verification returns `false`;
* decapsulate the DEK with an unrelated RSA key → `GeneralSecurityException`.

---

## 10. Project structure

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
README.md
```

---

## 11. Licensing and legal considerations

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

## 12. Project status

| Phase | Scope | State |
|---|---|---|
| 1 | Maven/Java 21 scaffolding, Bouncy Castle provider | ✅ |
| 2 | Cryptographic primitives and unit tests | ✅ |
| 3 | Domain model and authenticated JSON persistence | ✅ |
| 4 | Interactive CLI, registration/login, credential management, rotation | ✅ |
| 5 | End-to-end and abuse-scenario tests | ✅ |
| 6 | Standalone evidence programs and technical documentation | ✅ |

**63 tests pass** (`mvn clean test`). The three evidence programs run cleanly
through Maven and produce reproducible output. The project is intended for
academic demonstration, not production deployment.
