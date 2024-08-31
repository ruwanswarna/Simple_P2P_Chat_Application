import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ChatClient1 {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int PORT = 12345;
    private static SecretKey secretKey;
    private static PublicKey serverPublicKey;
    private static PrivateKey clientPrivateKey;
    private static PublicKey clientPublicKey;

    public static void main(String[] args) {
        try {
            // Generate RSA keys for the client
            KeyPair clientKeyPair = RSAUtils.generateKeyPair();
            clientPublicKey = clientKeyPair.getPublic();
            clientPrivateKey = clientKeyPair.getPrivate();

            try (Socket socket = new Socket(SERVER_ADDRESS, PORT);
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                 BufferedReader consoleInput = new BufferedReader(new InputStreamReader(System.in))) {

                // Send client public key to the server
                out.println(RSAUtils.publicKeyToString(clientPublicKey));
                System.out.println("Public key sent to server.");

                // Receive server public key
                String serverPublicKeyEncoded = in.readLine();
                serverPublicKey = RSAUtils.stringToPublicKey(serverPublicKeyEncoded);

                // Generate a new AES key
                secretKey = AESUtils.generateKey();

                // Encrypt the AES key with server's public key and send it
                byte[] encryptedSecretKey = RSAUtils.encrypt(serverPublicKey, secretKey.getEncoded());
                out.println(Base64.getEncoder().encodeToString(encryptedSecretKey));
                System.out.println("AES key sent to server.");

                // Create a thread to handle incoming messages from the server
                Thread serverHandler = new Thread(() -> {
                    String message;

                    System.out.print("Say something: ");
                    try {
                        
                        while ((message = in.readLine()) != null) {
                            // Split the received message into encrypted part and hash part
                            String[] parts = message.split("::");
                            if (parts.length == 2) {
                                String encryptedMessage = parts[0];
                                String receivedHash = parts[1];

                                // Decrypt the message
                                String decryptedMessage = AESUtils.decrypt(encryptedMessage, secretKey);

                                // Verify the integrity
                                if (HashUtils.verifyHash(decryptedMessage, receivedHash)) {
                                    System.out.println("\nServer says: " + decryptedMessage);
                                } else {
                                    System.out.println("\nMessage integrity check failed.");
                                }
                                System.out.print("Say something: ");
                            } else {
                                System.out.println("Invalid message format.");
                            }
                        }

                    } catch (Exception e) {
                        System.out.println("Connection lost.");
                    }
                });
                serverHandler.start();

                // Read messages from the console and send them to the server
                String userInput;
                while ((userInput = consoleInput.readLine()) != null) {
                    // Encrypt the message
                    String encryptedMessage = AESUtils.encrypt(userInput, secretKey);

                    // Compute the hash of the message
                    String hash = HashUtils.computeHash(userInput);

                    // Send the encrypted message and hash separated by "::"
                    out.println(encryptedMessage + "::" + hash);

                    System.out.print("Say something: ");

                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
