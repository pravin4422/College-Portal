package jun_26.util;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class PasswordUtil {

    public static String hash(String password) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        String saltB64 = Base64.getEncoder().encodeToString(salt);
        String hashB64 = sha256(saltB64 + password);
        return saltB64 + ":" + hashB64;
    }

    public static boolean verify(String password, String stored) throws Exception {
        String[] parts = stored.split(":", 2);
        if (parts.length != 2) return false;
        return sha256(parts[0] + password).equals(parts[1]);
    }

    private static String sha256(String input) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(input.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(hash);
    }
}
