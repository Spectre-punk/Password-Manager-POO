package src.passwordManager.model;

public class Credential {

    private String servicio; // pagina relacionada a la contraseña (google, discord, apple)
    private String nombreUsuario; // correo o usuario 
    private String contraseñaCifrada;
    private String notas;

    // constructores
    public Credential() {

    }

    public String getServicio() {
        return this.servicio;
    }

    public String getNombreUsuario() {
        return this.nombreUsuario;
    }

    public String getContraseñaCifrada() {
        return this.contraseñaCifrada;
    }

    public String getNotas() {
        return notas;
    }
}
