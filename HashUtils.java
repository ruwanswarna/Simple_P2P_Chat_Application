import java.security.MessageDigest;

public class HashUtils {

    private static final String SHA256 = "SHA-256";

    // Method to compute SHA-256 hash of a string
    public static String computeHash(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(SHA256);
        byte[] hashBytes = digest.digest(data.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Method to verify the hash against the original message
    public static boolean verifyHash(String data, String hash) throws Exception {
        String computedHash = computeHash(data);
        return computedHash.equals(hash);
    }
}
