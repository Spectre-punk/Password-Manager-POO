package passwordManager.util;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class GeneradorDeContraseñas {

    private final static int LENGTH = 15;
    private final static int BLOQUE = 4;

    public static String generarContraseña() {
        // por defualt tendra mayusculas, minusculas y numneros para mayor seguridad
        SecureRandom random = new SecureRandom();
        String chars = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZabcdefghijklmnñopqrstuvwxyz0123456789!@#$%&*()-";
        StringBuilder password = new StringBuilder();

        for (int i = 0; i < LENGTH; i++) {
            int index = random.nextInt(chars.length());
            password.append(chars.charAt(index));
            // cada 4 caracteres se añade un - para mejorar la legibilidad
            if ((i + 1) % BLOQUE == 0 && i + 1 < LENGTH) {
                password.append("-");
            }
        }
        return password.toString();
    }

    public static List<String> multiple(int cantidadDeContraseñas) {
        List<String> contraseñas = new ArrayList<>();
        for (int i = 0; i < cantidadDeContraseñas; i++) {
            contraseñas.add(generarContraseña());
        }
        return contraseñas;
    }
}
