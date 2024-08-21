import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HashUtils {
    // Compute SHA-256 hash of a message
    public static String computeSHA256(String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(message.getBytes());
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    // Verify the integrity of a message by comparing hash values
    public static boolean verifyMessageIntegrity(String message, String receivedHash) throws NoSuchAlgorithmException {
        String computedHash = computeSHA256(message);
        return computedHash.equals(receivedHash);
    }
}
