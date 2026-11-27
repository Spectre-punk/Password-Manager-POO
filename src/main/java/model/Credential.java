package model;

import java.util.Arrays;
import java.util.Objects;

/**
 * Plain credential record stored inside the encrypted vault block.
 *
 * <p>This is a pure POJO: it performs no encryption or decryption. The whole
 * list of credentials is serialized and encrypted as a single AES-GCM blob by
 * {@code storage.PersistenciaBoveda}.</p>
 *
 * <p>The secret is held as {@code char[]} (never a {@link String}) and can be
 * wiped with {@link #clearPassword()}.</p>
 */
public class Credential {

    private String servicio;
    private String nombreUsuario;
    private char[] contrasena;
    private String notas;

    /** Required by Gson. */
    public Credential() {
    }

    public Credential(String servicio, String nombreUsuario, char[] contrasena, String notas) {
        this.servicio = servicio;
        this.nombreUsuario = nombreUsuario;
        setContrasena(contrasena);
        this.notas = notas;
    }

    public String getServicio() {
        return servicio;
    }

    public void setServicio(String servicio) {
        this.servicio = servicio;
    }

    public String getNombreUsuario() {
        return nombreUsuario;
    }

    public void setNombreUsuario(String nombreUsuario) {
        this.nombreUsuario = nombreUsuario;
    }

    /** @return a defensive copy of the secret, or {@code null} if cleared */
    public char[] getContrasena() {
        return contrasena == null ? null : contrasena.clone();
    }

    public void setContrasena(char[] contrasena) {
        clearPassword();
        this.contrasena = contrasena == null ? null : contrasena.clone();
    }

    public String getNotas() {
        return notas;
    }

    public void setNotas(String notas) {
        this.notas = notas;
    }

    /** Wipes the in-memory secret. */
    public void clearPassword() {
        if (contrasena != null) {
            Arrays.fill(contrasena, '\0');
            contrasena = null;
        }
    }

    @Override
    public String toString() {
        return "Credential{servicio='" + servicio + '\''
                + ", nombreUsuario='" + nombreUsuario + '\''
                + ", notas='" + notas + '\''
                + ", contrasena=<protected>}";
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Credential that)) {
            return false;
        }
        return Objects.equals(servicio, that.servicio)
                && Objects.equals(nombreUsuario, that.nombreUsuario)
                && Objects.equals(notas, that.notas);
    }

    @Override
    public int hashCode() {
        return Objects.hash(servicio, nombreUsuario, notas);
    }
}
