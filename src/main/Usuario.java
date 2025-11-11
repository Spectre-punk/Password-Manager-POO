package main;

public abstract class Usuario {

    protected boolean accesoTotal = false;
    protected String nombreDeUsuario;

    public String obtenerNombre() {
        return this.nombreDeUsuario;
    }
}
