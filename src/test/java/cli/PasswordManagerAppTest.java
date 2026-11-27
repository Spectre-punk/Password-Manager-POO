package cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Provider;
import java.security.Security;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

class PasswordManagerAppTest {

    @Test
    void registersBouncyCastleProviderAtStartup() {
        PasswordManagerApp.registerSecurityProvider();

        Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(provider, "Bouncy Castle must be registered");
        assertEquals(BouncyCastleProvider.PROVIDER_NAME, provider.getName());
    }

    @Test
    void registrationIsIdempotent() {
        PasswordManagerApp.registerSecurityProvider();
        PasswordManagerApp.registerSecurityProvider();

        long matches = java.util.Arrays.stream(Security.getProviders())
                .filter(p -> BouncyCastleProvider.PROVIDER_NAME.equals(p.getName()))
                .count();
        assertEquals(1, matches, "Provider must be registered exactly once");
    }

    @Test
    void bouncyCastleProvidesAesGcm() throws Exception {
        PasswordManagerApp.registerSecurityProvider();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(cipher);
        assertTrue(cipher.getProvider() instanceof BouncyCastleProvider);
    }
}
