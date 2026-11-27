## Mental model: four layers

```
cli/         interactive shell (Main)          ← user I/O, menu
model/       domain + session (Gestor, UsuarioMaestro, Credential)
storage/     vault file format + persistence (PersistenciaBoveda, VaultFile)
crypto/      primitives (Argon2, AES-GCM, RSA-OAEP, Ed25519, Schnorr)
util/        helpers (SecretWiper, password generator)
evidencias/  standalone IND1/IND2/IND3 demos
```

Read it **bottom-up**: primitives first, then how they are combined.

## Recommended reading order

| Step | Files | What to learn |
|---|---|---|
| 1 | `README.md` | Threat model, key hierarchy, design rationale |
| 2 | `model/Credential.java`, `util/SecretWiper.java` | Simple POJO; why secrets are `char[]`/`byte[]` and wiped |
| 3 | `crypto/Argon2KDF.java` | 64-byte output split into KEK + Schnorr seed |
| 4 | `crypto/VaultCipher.java` | AES-256-GCM encrypt/decrypt, fresh nonce, tag |
| 5 | `crypto/KeyEncapsulator.java` | RSA-OAEP wraps/unwraps the DEK (IND1) |
| 6 | `crypto/DigitalSigner.java` | Ed25519 sign/verify (IND2) |
| 7 | `crypto/SchnorrZKP.java` | Registration `Y=g^x`, 3-move proof (IND3) |
| 8 | `storage/VaultFile.java` | Plain DTO: payload + signature |
| 9 | `storage/PersistenciaBoveda.java` | Save/load, **verify signature before decrypt**, rewrap |
| 10 | `model/UsuarioMaestro.java` | Metadata, ZKP auth, KEK-encrypted private keys, `reencrypt` |
| 11 | `model/Gestor.java` | Singleton session: DEK, credentials, `lock()`, rotation |
| 12 | `cli/Main.java` | Registration, login, menu, secure input |
| 13 | `src/test/java/security/` | End-to-end + abuse scenarios as executable docs |

## The five flows to trace

1. **Registration**  
   `Main.register` → `Gestor.inicializar` → `UsuarioMaestro.create` (salt, Argon2 → KEK + Schnorr seed, `Y`, RSA/Ed25519 keypairs, private keys encrypted with KEK) → random DEK → `PersistenciaBoveda.save` (credentials JSON → AES-GCM with DEK; DEK → RSA-OAEP; payload → Ed25519; atomic write).

2. **Login**  
   `PersistenciaBoveda.read` verifies the Ed25519 signature **first** → `Gestor.desbloquear` → `UsuarioMaestro.unlock` (Argon2 → Schnorr proof against `Y` → decrypt private keys with KEK) → decapsulate DEK → decrypt credentials.

3. **Add credential**  
   `Main.addCredential` → `Gestor.agregarCredencial` → `Gestor.guardar` → `PersistenciaBoveda.save`.

4. **Change master password**  
   `Gestor.cambiarContraseñaMaestra` → authenticate old password → `UsuarioMaestro.reencrypt` (new salt/verifier/KEK, same keypairs) → `PersistenciaBoveda.rewrap` (re-wrap DEK, **reuse credentials IV/ciphertext**, re-sign).

5. **Lock / exit**  
   `Gestor.lock` zeroizes the DEK, clears credentials, drops private-key references.

## Key ideas to keep in mind

- **Two keys, two jobs**: KEK (from password) protects private keys; random DEK protects credentials. Rotation changes the KEK, not the DEK.
- **Domain separation**: Argon2’s first 32 bytes = KEK, last 32 = Schnorr secret seed.
- **Verify before decrypt**: no AES-GCM is attempted until Ed25519 passes.
- **No password hash at rest**: `Y` is a public verifier; login is a ZKP.
- **No `String` for secrets**: passwords are `char[]`, keys `byte[]`, wiped after use.
- **AEAD everywhere**: no ECB, no CBC-without-MAC.

## Practical study tips

- Open each test next to its class: `Argon2KDFTest`, `VaultCipherTest`, `KeyEncapsulatorTest`, `DigitalSignerTest`, `SchnorrZKPTest`, then `PersistenciaBovedaTest`, `GestorTest`, `MainTest`, `security/*`.
- Run the isolated demos to see primitives without the CLI:
  ```bash
  mvn exec:java -Dexec.mainClass=evidencias.EvidenciaKEM
  mvn exec:java -Dexec.mainClass=evidencias.EvidenciaFirma
  mvn exec:java -Dexec.mainClass=evidencias.EvidenciaZKP
  ```
- Trace one credential end-to-end: add it in the CLI, inspect `boveda.json` (you’ll see only Base64 ciphertext), restart, view it.
- Use `git log --oneline` to see the phase-by-phase construction; each commit maps to one layer.
- Draw the key hierarchy once; almost every class is just one arrow in that diagram.