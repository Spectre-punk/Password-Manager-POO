package src.passwordManager.model;
import src.passwordManager.crypto.CryptoUtils;
import javax.crypto.SecretKey;
import src.passwordManager.exceptions.CryptoException;

public class CredentialEntry extends Entry {
    private String site, username, notes;
    private String salt;
    private byte[] encryptedSecret;

    protected CredentialEntry(String tittle, String site, String username, String plainPassword, EntryType type){
        super(tittle, type);
        setSite(site);
        this.username = username;
    }

    protected String getSite() {
        return site;
    }

    protected void setSite(String site) {
        if (site != null && !site.isEmpty()) {
            this.site = site;
        } else {
            System.out.println("excepcion");
        }
    }

    protected String getUsername() {
        return username;
    }

    protected void setUsername(String username) {
        if (username != null && !username.isEmpty()) {
            this.username = username;
        } else {
            System.out.println("excepcion");
        }
    }

    protected byte[] getEncryptedSecret() {
        return encryptedSecret;
    }
    /*
     * getDecryptedSecret(SecretKey masterKey) — comportamiento: recibe la clave
     * maestra derivada por Vault/CryptoUtils, usa CryptoUtils para descifrar y
     * devuelve String con la contraseña en texto plano. (Si la implementación no
     * puede descifrar, que lance CryptoException).
     */

    /*
     * setSecretFromPlain(String plainPassword, SecretKey masterKey) — cifra y
     * guarda en encryptedSecret
     */
    private void setSecretFromPlain(String plainPassword, SecretKey masterKey){
        this.encryptedSecret = CryptoUtils.encrypt(plainPassword, masterKey);
    }
    public String getDecryptedSecret(SecretKey masterKey) throws CryptoException {
        try {
            return CryptoUtils.decrypt(this.encryptedSecret, masterKey);
        } catch (Exception e) {
            throw new CryptoException("Error decrypting secret:" + e.getMessage());
        }
    }
}
