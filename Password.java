public class Password {
    private String password;
    private final int MIN_LENGTH = 8;
    private final int MAX_LENGTH = 16;

    public Password(String password) {
        setPassword(password);
    }
    public String getPassword() {
        return password; 
    }
    public void setPassword(String password) {
        if (password.length() >= MIN_LENGTH && password.length() <= MAX_LENGTH) {
            this.password = password;
        } else {
            throw new IllegalArgumentException("La contraseña debe tener entre " + MIN_LENGTH + " y " + MAX_LENGTH + " caracteres.");
        }
    }

}
