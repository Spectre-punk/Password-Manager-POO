package model;

/**
 * Base type for users of the password manager.
 *
 * <p>Holds only public identity data. No password material lives here.</p>
 */
public abstract class Usuario {

    protected String nombreDeUsuario;

    public String getNombreDeUsuario() {
        return nombreDeUsuario;
    }

    public void setNombreDeUsuario(String nombreDeUsuario) {
        this.nombreDeUsuario = nombreDeUsuario;
    }
}
