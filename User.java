public class User {
    private String username;

    public User(String username, String password) {
        setUsername(username);
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        if (username != null && !username.trim().isEmpty()) {
            this.username = username;
        } else {
            throw new IllegalArgumentException("El nombre de usuario no puede estar vacío.");
        }
    }
}
