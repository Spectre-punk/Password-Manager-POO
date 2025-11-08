package src.passwordManager.model;

import src.passwordManager.crypto.CryptoUtils;
import javax.crypto.SecretKey;
import src.passwordManager.exceptions.CryptoException;
import src.passwordManager.exceptions.InvalidEntryException;

public class CredentialEntry extends Entry {
    private String site, username, notes;
    private String salt;
    private byte[] encryptedSecret;

    public CredentialEntry(String title, String site, String username, String plainPassword, EntryType type){
        super(title, type);
        setSite(site);
        setUsername(username);
        // setSecretFromPlain(plainPassword, masterKey) se hace cuando tengas la clave
    }

    public String getSite() {
        return site;
    }

    public void setSite(String site) {
        if (site == null || site.isEmpty())
            throw new IllegalArgumentException("site cannot be null or empty");
        this.site = site;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        if (username == null || username.isEmpty())
            throw new IllegalArgumentException("username cannot be null or empty");
        this.username = username;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    public byte[] getEncryptedSecret() {
        return encryptedSecret;
    }

    public void setSecretFromPlain(String plainPassword, SecretKey masterKey) throws CryptoException {
        try {
            this.encryptedSecret = CryptoUtils.encrypt(plainPassword, masterKey);
        } catch (Exception e) {
            throw new CryptoException("Error encrypting secret: " + e.getMessage());
        }
    }

    public String getDecryptedSecret(SecretKey masterKey) throws CryptoException {
        try {
            return CryptoUtils.decrypt(this.encryptedSecret, masterKey);
        } catch (Exception e) {
            throw new CryptoException("Error decrypting secret: " + e.getMessage());
        }
    }

    @Override
    public String toString() {
        return "CredentialEntry{id=" + getId() + ", title=" + getTitle() + ", type=" + getType() +
                ", site=" + site + ", username=" + username + ", notes=" + notes + "}";
    }
}
