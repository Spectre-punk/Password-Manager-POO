package cli;

import java.io.Console;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import model.Credential;
import model.Gestor;
import storage.PersistenciaBoveda;
import storage.VaultFile;
import util.GeneradorDeContraseñas;
import util.SecretWiper;

/**
 * Interactive single-user CLI for the password manager.
 *
 * <p>Passwords are read with {@link Console#readPassword()} when a terminal is
 * available, falling back to a line-based {@link Scanner} for IDEs/pipes.
 * Secrets are held as {@code char[]} and wiped after use.</p>
 */
public final class Main {

    private static final int MAX_LOGIN_ATTEMPTS = 3;

    private static Scanner fallbackScanner;
    private static boolean consoleEnabled = true;

    private Main() {
        throw new AssertionError("No instances.");
    }

    public static void main(String[] args) {
        int code = run(args);
        if (code != 0) {
            System.exit(code);
        }
    }

    /**
     * Runs the CLI without calling {@link System#exit(int)} (testable entry point).
     *
     * @param args optional vault path; defaults to {@code boveda.json}
     * @return process-style exit code
     */
    public static int run(String[] args) {
        PasswordManagerApp.registerSecurityProvider();

        Path vaultPath = args.length > 0
                ? Path.of(args[0])
                : Path.of(PersistenciaBoveda.DEFAULT_FILE_NAME);
        fallbackScanner = new Scanner(System.in);
        Gestor gestor = Gestor.getInstancia();

        try {
            gestor.lock();
            if (Files.exists(vaultPath)) {
                login(vaultPath);
            } else {
                register(vaultPath);
            }
            menu();
            return 0;
        } catch (SecurityException e) {
            System.err.println("Security error: " + e.getMessage());
            return 2;
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            return 1;
        } finally {
            gestor.lock();
            fallbackScanner = null;
        }
    }

    /** Test hook: force the Scanner fallback even if a console is attached. */
    static void setConsoleEnabled(boolean enabled) {
        consoleEnabled = enabled;
    }

    private static void register(Path vaultPath) throws Exception {
        System.out.println("No vault found. First-run registration.");

        String username = readLine("Username: ");
        if (username == null || username.isBlank()) {
            throw new SecurityException("Username is required");
        }

        char[] password = readPassword("Master password: ");
        char[] confirm = readPassword("Confirm master password: ");
        try {
            if (password == null || password.length == 0) {
                throw new SecurityException("Master password cannot be empty");
            }
            if (confirm == null || !Arrays.equals(password, confirm)) {
                throw new SecurityException("Passwords do not match");
            }

            Gestor.getInstancia().inicializar(vaultPath, username.trim(), password);
            System.out.println("Vault created: " + vaultPath.toAbsolutePath());
        } finally {
            SecretWiper.wipe(password);
            SecretWiper.wipe(confirm);
        }
    }

    private static void login(Path vaultPath) throws Exception {
        // Verify the Ed25519 signature before asking for the password.
        VaultFile file = PersistenciaBoveda.read(vaultPath);

        for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {
            char[] password = readPassword("Master password: ");
            try {
                if (password == null || password.length == 0) {
                    System.err.println("Password cannot be empty.");
                    continue;
                }
                Gestor.getInstancia().desbloquear(file, vaultPath, password);
                System.out.println("Vault unlocked.");
                return;
            } catch (SecurityException e) {
                System.err.println("Invalid master password ("
                        + attempt + "/" + MAX_LOGIN_ATTEMPTS + ").");
            } finally {
                SecretWiper.wipe(password);
            }
        }
        throw new SecurityException("Too many failed login attempts");
    }

    private static void menu() throws Exception {
        while (true) {
            printMenu();
            String choice = readLine("Option: ");
            if (choice == null) {
                System.out.println();
                System.out.println("End of input.");
                return;
            }

            switch (choice.trim()) {
                case "1" -> addCredential();
                case "2" -> listCredentials();
                case "3" -> viewCredential();
                case "4" -> changeMasterPassword();
                case "5" -> {
                    Gestor.getInstancia().guardar();
                    System.out.println("Saved. Exiting.");
                    return;
                }
                case "0" -> {
                    System.out.println("Exiting without saving.");
                    return;
                }
                default -> System.out.println("Unknown option.");
            }
        }
    }

    private static void printMenu() {
        System.out.println();
        System.out.println("=== Password Manager ===");
        System.out.println("1. Add credential");
        System.out.println("2. List credentials");
        System.out.println("3. View credential details");
        System.out.println("4. Change master password");
        System.out.println("5. Save, wipe memory and exit");
        System.out.println("0. Exit without saving");
    }

    private static void addCredential() throws Exception {
        String servicio = readLine("Service: ");
        String usuario = readLine("Username/email: ");
        String notas = readLine("Notes: ");
        if (servicio == null || usuario == null || notas == null) {
            System.out.println("Input closed; credential not added.");
            return;
        }
        if (servicio.isBlank() || usuario.isBlank()) {
            System.out.println("Service and username are required.");
            return;
        }

        String generate = readLine("Generate a password? (y/N): ");
        boolean generated = generate != null && generate.trim().equalsIgnoreCase("y");

        char[] password;
        if (generated) {
            password = GeneradorDeContraseñas.generarContraseña();
            System.out.print("Generated password: ");
            System.out.print(password);
            System.out.println();
        } else {
            password = readPassword("Password: ");
        }

        try {
            if (password == null || password.length == 0) {
                System.out.println("Password cannot be empty; credential not added.");
                return;
            }
            Gestor gestor = Gestor.getInstancia();
            gestor.agregarCredencial(new Credential(
                    servicio.trim(), usuario.trim(), password, notas.trim()));
            gestor.guardar();
            System.out.println("Credential added and saved.");
        } finally {
            SecretWiper.wipe(password);
        }
    }

    private static void listCredentials() {
        List<Credential> credentials = Gestor.getInstancia().getCredenciales();
        if (credentials.isEmpty()) {
            System.out.println("No credentials stored.");
            return;
        }
        for (int i = 0; i < credentials.size(); i++) {
            Credential credential = credentials.get(i);
            System.out.printf("%d. %s | %s | %s%n",
                    i + 1,
                    credential.getServicio(),
                    credential.getNombreUsuario(),
                    credential.getNotas());
        }
    }

    private static void viewCredential() {
        List<Credential> credentials = Gestor.getInstancia().getCredenciales();
        if (credentials.isEmpty()) {
            System.out.println("No credentials stored.");
            return;
        }

        listCredentials();
        Integer index = readInt("Credential number: ");
        if (index == null) {
            return;
        }
        if (index < 1 || index > credentials.size()) {
            System.out.println("Invalid credential number.");
            return;
        }

        Credential credential = credentials.get(index - 1);
        System.out.println("Service: " + credential.getServicio());
        System.out.println("Username: " + credential.getNombreUsuario());
        System.out.println("Notes: " + credential.getNotas());

        char[] password = credential.getContrasena();
        try {
            if (password == null) {
                System.out.println("Password: <cleared>");
            } else {
                System.out.print("Password: ");
                System.out.print(password);
                System.out.println();
            }
        } finally {
            SecretWiper.wipe(password);
        }
    }

    private static void changeMasterPassword() throws Exception {
        char[] current = readPassword("Current master password: ");
        char[] next = readPassword("New master password: ");
        char[] confirm = readPassword("Confirm new master password: ");
        try {
            if (current == null || next == null || confirm == null) {
                System.out.println("Input closed; password not changed.");
                return;
            }
            if (next.length == 0) {
                System.out.println("New password cannot be empty.");
                return;
            }
            if (!Arrays.equals(next, confirm)) {
                System.out.println("New passwords do not match.");
                return;
            }

            try {
                Gestor.getInstancia().cambiarContraseñaMaestra(current, next);
                System.out.println("Master password changed and vault saved.");
            } catch (SecurityException e) {
                System.out.println("Invalid current master password; nothing changed.");
            }
        } finally {
            SecretWiper.wipe(current);
            SecretWiper.wipe(next);
            SecretWiper.wipe(confirm);
        }
    }

    private static String readLine(String prompt) {
        Console console = consoleEnabled ? System.console() : null;
        if (console != null) {
            return console.readLine("%s", prompt);
        }
        System.out.print(prompt);
        if (fallbackScanner == null || !fallbackScanner.hasNextLine()) {
            return null;
        }
        return fallbackScanner.nextLine();
    }

    private static char[] readPassword(String prompt) {
        Console console = consoleEnabled ? System.console() : null;
        if (console != null) {
            return console.readPassword("%s", prompt);
        }
        System.out.print(prompt);
        if (fallbackScanner == null || !fallbackScanner.hasNextLine()) {
            return null;
        }
        return fallbackScanner.nextLine().toCharArray();
    }

    private static Integer readInt(String prompt) {
        while (true) {
            String line = readLine(prompt);
            if (line == null) {
                return null;
            }
            try {
                return Integer.parseInt(line.trim());
            } catch (NumberFormatException e) {
                System.out.println("Please enter a number.");
            }
        }
    }
}
