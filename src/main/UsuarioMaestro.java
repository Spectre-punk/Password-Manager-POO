package main;

import crypto.Hashing;

public class UsuarioMaestro extends Usuario implements Hashing {

    private final String salt;
    private String hashContraseñaMaestra;

    public UsuarioMaestro(String inputPassword) {
        this.salt = Hashing.generateSalt();
        if (autenticar(inputPassword)) {
            tieneAccessoTotal();
        } else {
            System.out.println("contraseña incorrecta");
        }
    }

    private boolean autenticar(String inputPassword) {
        // hashear contraseña y compararla con el hash correcto
        return Hashing.verifyPassword(inputPassword, hashContraseñaMaestra, this.salt);
    }

    public String getHashContraseñaMaestra() {
        return hashContraseñaMaestra;
    }

    @Override
    void tieneAccessoTotal() {
        this.accesoTotal = true;
    }
}
