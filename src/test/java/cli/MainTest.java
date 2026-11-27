package cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import model.Gestor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MainTest {

    private static final String MASTER_PASSWORD = "Master-Pass-123!";

    @BeforeEach
    void forceFallbackInput() {
        Main.setConsoleEnabled(false);
    }

    @AfterEach
    void lockVault() {
        Gestor.getInstancia().lock();
    }

    @Test
    void fullLifecyclePersistsAcrossRestarts(@TempDir Path dir) throws Exception {
        Path vault = dir.resolve("boveda.json");

        Result registration = runCli(vault,
                "alice",
                MASTER_PASSWORD,
                MASTER_PASSWORD,
                "1",
                "github",
                "alice",
                "work account",
                "n",
                "s3cret",
                "5");
        assertEquals(0, registration.exitCode(), registration.stderr());
        assertTrue(registration.stdout().contains("Vault created"));
        assertTrue(registration.stdout().contains("Credential added and saved"));
        assertTrue(Files.exists(vault), "the vault must be written on first run");

        Result listing = runCli(vault,
                MASTER_PASSWORD,
                "2",
                "5");
        assertEquals(0, listing.exitCode(), listing.stderr());
        assertTrue(listing.stdout().contains("Vault unlocked"));
        assertTrue(listing.stdout().contains("github"));
        assertTrue(listing.stdout().contains("work account"));
        assertFalse(listing.stdout().contains("s3cret"),
                "listing must never reveal stored passwords");

        Result viewing = runCli(vault,
                MASTER_PASSWORD,
                "3",
                "1",
                "0");
        assertEquals(0, viewing.exitCode(), viewing.stderr());
        assertTrue(viewing.stdout().contains("Password: s3cret"));

        // The credential survives a further restart unchanged.
        Result relisting = runCli(vault,
                MASTER_PASSWORD,
                "2",
                "0");
        assertEquals(0, relisting.exitCode(), relisting.stderr());
        assertTrue(relisting.stdout().contains("github"));
    }

    @Test
    void rejectsWrongMasterPasswordWithoutUnlocking(@TempDir Path dir) throws Exception {
        Path vault = dir.resolve("boveda.json");

        Result registration = runCli(vault,
                "alice",
                MASTER_PASSWORD,
                MASTER_PASSWORD,
                "5");
        assertEquals(0, registration.exitCode(), registration.stderr());

        Result rejected = runCli(vault,
                "wrong-password",
                "wrong-password",
                "wrong-password");
        assertEquals(2, rejected.exitCode());
        assertTrue(rejected.stderr().contains("Too many failed login attempts"));
        assertTrue(Gestor.getInstancia().isLocked());
    }

    @Test
    void changesMasterPasswordThroughMenu(@TempDir Path dir) throws Exception {
        Path vault = dir.resolve("boveda.json");
        String newPassword = "New-Master-Pass-456!";

        Result registration = runCli(vault,
                "alice",
                MASTER_PASSWORD,
                MASTER_PASSWORD,
                "1",
                "mail",
                "alice@example.com",
                "personal",
                "n",
                "hunter2",
                "4",
                MASTER_PASSWORD,
                newPassword,
                newPassword,
                "5");
        assertEquals(0, registration.exitCode(), registration.stderr());
        assertTrue(registration.stdout().contains("Master password changed and vault saved"));

        Result oldPassword = runCli(vault,
                MASTER_PASSWORD,
                MASTER_PASSWORD,
                MASTER_PASSWORD);
        assertEquals(2, oldPassword.exitCode());
        assertTrue(oldPassword.stderr().contains("Too many failed login attempts"));

        Result newPasswordRun = runCli(vault,
                newPassword,
                "3",
                "1",
                "0");
        assertEquals(0, newPasswordRun.exitCode(), newPasswordRun.stderr());
        assertTrue(newPasswordRun.stdout().contains("Password: hunter2"));
    }

    private static Result runCli(Path vault, String... lines) {
        StringBuilder input = new StringBuilder();
        for (String line : lines) {
            input.append(line).append(System.lineSeparator());
        }

        InputStream originalIn = System.in;
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();

        try {
            System.setIn(new ByteArrayInputStream(
                    input.toString().getBytes(StandardCharsets.UTF_8)));
            System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
            System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));

            int exitCode = Main.run(new String[]{vault.toString()});
            return new Result(exitCode,
                    out.toString(StandardCharsets.UTF_8),
                    err.toString(StandardCharsets.UTF_8));
        } finally {
            System.setIn(originalIn);
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
    }

    private record Result(int exitCode, String stdout, String stderr) {
    }
}
