package cli;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * CLI entry point for the password manager.
 *
 * <p>Registers Bouncy Castle as a JCA/JCE provider exactly once, globally, at
 * application startup so every cryptographic operation in the application can
 * rely on a consistent provider.</p>
 */
public final class PasswordManagerApp {

    private PasswordManagerApp() {
        throw new AssertionError("No instances.");
    }

    public static void main(String[] args) {
        registerSecurityProvider();

        System.out.println("Password Manager started. Crypto provider: "
                + Security.getProvider(BouncyCastleProvider.PROVIDER_NAME).getName());
    }

    /**
     * Registers Bouncy Castle globally via {@link Security#addProvider(java.security.Provider)}.
     *
     * <p>Idempotent: calling it more than once will not register duplicate providers.
     * Exposed as public so both the CLI bootstrap and the test suite share the same
     * registration path.</p>
     */
    public static void registerSecurityProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
