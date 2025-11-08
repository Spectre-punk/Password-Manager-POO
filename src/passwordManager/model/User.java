package src.passwordManager.model;

public class User {
    private String username;
    private String masterPasswordHash;
    private String salt;
    private String iterations;
    Vault vault;

    public boolean validateMasterPassword(String attempt) {
        return true;
        /*
         * compara derivación/hash; devuelve boolean. Si hash inválido, lanza
         * InvalidMasterPasswordException o devuelve false.
         */
    }
    public void setMasterPassword(String newPassword){
        /*
         * derivar hash + salt, actualizar
         * masterPasswordHash
         */
    }
    public void setVault(Vault v){
        this.vault = v;
    }
    public Vault geVault(){
        return vault;
    }
    public String getUsername(){
        return username;
    }
    public void setUsername(String username){
        this.username = username;
    }
}
