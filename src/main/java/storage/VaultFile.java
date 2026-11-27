package storage;

import model.UsuarioMaestro;

/**
 * On-disk vault representation, serialized with Gson.
 *
 * <p>The signed payload contains the master-user metadata, the KEM-wrapped DEK
 * and the AES-GCM encrypted credentials blob. {@link #signature} is the
 * Base64-encoded Ed25519 signature over the canonical JSON of {@link #payload}.</p>
 */
public class VaultFile {

    private VaultPayload payload;
    private String signature;

    /** Required by Gson. */
    public VaultFile() {
    }

    public VaultPayload getPayload() {
        return payload;
    }

    public void setPayload(VaultPayload payload) {
        this.payload = payload;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    /** Everything that is covered by the Ed25519 signature. */
    public static class VaultPayload {

        private UsuarioMaestro usuario;
        private String encapsulatedDek;
        private String credentialsIv;
        private String credentialsCiphertext;

        /** Required by Gson. */
        public VaultPayload() {
        }

        public UsuarioMaestro getUsuario() {
            return usuario;
        }

        public void setUsuario(UsuarioMaestro usuario) {
            this.usuario = usuario;
        }

        public String getEncapsulatedDek() {
            return encapsulatedDek;
        }

        public void setEncapsulatedDek(String encapsulatedDek) {
            this.encapsulatedDek = encapsulatedDek;
        }

        public String getCredentialsIv() {
            return credentialsIv;
        }

        public void setCredentialsIv(String credentialsIv) {
            this.credentialsIv = credentialsIv;
        }

        public String getCredentialsCiphertext() {
            return credentialsCiphertext;
        }

        public void setCredentialsCiphertext(String credentialsCiphertext) {
            this.credentialsCiphertext = credentialsCiphertext;
        }
    }
}
