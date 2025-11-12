package crypto;

import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CifradoUtil {

    private static SecretKey key;
    private static Cipher encryptionCipher;
    private static Cipher decryptionCipher;

    public static void init() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        key = generator.generateKey();
    }

    public static SecretKey getKey() {
        return key;
    }

    public static String cifrar(String s) throws Exception {
        if (key == null) {
            throw new IllegalStateException("Key not initialized. Call init() fist");
        }
        return cifrar(s, key);
    }

    private static String cifrar(String s, SecretKey k) throws Exception {
        encryptionCipher = Cipher.getInstance("AES");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, k);
        byte[] textoCifrado = encryptionCipher.doFinal(s.getBytes());
        return encode(textoCifrado);
    }

    private static String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private static byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public static String descifrar(String s) throws Exception {
        if (key == null) {
            throw new IllegalStateException("Key not initialized. Call init() first");
        }
        return descifrar(s, key);
    }

    private static String descifrar(String textoCifrado, SecretKey k) throws Exception {
        byte[] messageInBytes = decode(textoCifrado);
        decryptionCipher = Cipher.getInstance("AES");
        // param espec
        decryptionCipher.init(Cipher.DECRYPT_MODE, k);
        byte[] textoDescifrado = decryptionCipher.doFinal(messageInBytes);
        return new String(textoDescifrado);
    }
}
