package main;

import crypto.Hashing;

public class UsuarioMaestro extends Usuario implements Hashing {

    private static UsuarioMaestro superUsuario;
    private final String salt;
    private String hashContraseñaMaestra;

    private UsuarioMaestro(String nuevaContraseña, String nombreDeUsuario) {
        this.salt = Hashing.generateSalt();
        this.nombreDeUsuario = nombreDeUsuario;
        crearUsuarioMaestro(nuevaContraseña);
    }

    public static UsuarioMaestro obtenerInstancia(String nombreDeUsuario, String inputPassword) {
        if (superUsuario == null) {
            superUsuario = new UsuarioMaestro(inputPassword, nombreDeUsuario);
            superUsuario.tieneAccessoTotal();
        }
        return superUsuario;
        // comentario
    }

    private boolean autenticar(String inputPassword) {
        // hashear contraseña y compararla con el hash correcto
        return Hashing.verifyPassword(inputPassword, hashContraseñaMaestra, this.salt);
    }

    public String getHashContraseñaMaestra() {
        return hashContraseñaMaestra;
    }

    private void tieneAccessoTotal() {
        this.accesoTotal = true;
    }

    private void crearUsuarioMaestro(String inputContraseña) {
        this.hashContraseñaMaestra = Hashing.hashPassword(inputContraseña, salt);
    }

    public void establecerContraseña(String nuevaContraseña, String inputPassword) {
        if (autenticar(inputPassword)) {
            crearUsuarioMaestro(nuevaContraseña);
        } else {
            System.out.println("contraseña incorrecta");
        }
    }
}
/*
private UsuarioMaestro(String nuevaContraseña) {
        this.salt = Hashing.generateSalt();
        crearUsuario(nuevaContraseña); // Inicializa la contraseña hasheada
    }

    public static UsuarioMaestro obtenerInstancia(String nuevaContraseña) {
        if (instancia == null) {
            instancia = new UsuarioMaestro(nuevaContraseña);
        }
        return instancia;
    }

    private void crearUsuario(String nuevaContraseña) {
        this.hashContraseñaMaestra = Hashing.hashPassword(nuevaContraseña, this.salt);
    }

    public void establecerContraseña(String nuevaContraseña, String inputPassword) {
        if (autenticar(inputPassword)) {
            crearUsuario(nuevaContraseña);
        } else {
            System.out.println("Contraseña incorrecta. No se puede cambiar la contraseña maestra.");
        }
    }
 */
