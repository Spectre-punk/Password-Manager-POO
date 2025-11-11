package passwordManager.main;

import crypto.*;

public class UsuarioMaestro extends Usuario {

    private byte[] hashContraseñaMaestra;
    private byte[] salt;

    public UsuarioMaestro(String contraseñaSuperUsuario) {
        if (autenticar(contraseñaSuperUsuario)) {
            tieneAccessoTotal();
        } else {
            System.out.println("contraseña incorrecta");
        }
    }

    private boolean autenticar(String contraseñaSuperUsuario) {
        // hashear contraseña y compararla con el hash correcto
        this.salt = Hashing.generateSalt();
        byte[] contraseñaHasheada;
        return contraseñaHasheada.equals(hashContraseñaMaestra);
    }

    public byte[] getHashContraseñaMaestra() {
        return hashContraseñaMaestra;
    }

    private void tieneAccessoTotal() {
        this.accesoTotal = true;
    }
}
