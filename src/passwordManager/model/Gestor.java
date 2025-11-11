package src.passwordManager.model;

import java.security.Key;
import java.util.List;
import java.util.ArrayList;

public class Gestor {

    private Gestor gestor;
    // clase de tipo singleton una unica instancia dentro del programa
    private List<Credential> credenciales = new ArrayList<>(); // es donde se guardaron los todas las contraseñas y donde se haran la mayoria de las operaciones
    PersistenciaDeDatos almacenador;
    Key claveMaestra;

    private Gestor() {
        if (gestor == null) {
            gestor = new Gestor(); //pasar parametros
        }
    }

    private Gestor(Key claveMaestra) {
        this.claveMaestra = claveMaestra;
    }

    public Gestor getInstancia() {
        return this.gestor;
    }

    public void agregarCredencial() {

    }

    public void guardarDatos() {

    }
}
