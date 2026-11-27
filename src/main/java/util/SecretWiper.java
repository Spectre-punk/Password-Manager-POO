package util;

import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

/** Best-effort zeroization helpers for in-memory secrets. */
public final class SecretWiper {

    private SecretWiper() {
        throw new AssertionError("No instances.");
    }

    public static void wipe(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }

    public static void wipe(char[] data) {
        if (data != null) {
            Arrays.fill(data, '\0');
        }
    }

    public static void destroy(Destroyable destroyable) {
        if (destroyable != null) {
            try {
                destroyable.destroy();
            } catch (DestroyFailedException ignored) {
                // Best effort only.
            }
        }
    }
}
