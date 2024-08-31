import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ChatClient2 {
    private static final int PORT = 12345;
    private static SecretKey secretKey;
    private static PublicKey clientPublicKey;
    private static PrivateKey serverPrivateKey;
    private static PublicKey serverPublicKey;

    public static void main(String[] args) {
        try {
            // Generate RSA keys for the server
            KeyPair serverKeyPair = RSAUtils.generateKeyPair();
            serverPublicKey = serverKeyPair.getPublic();
            serverPrivateKey = serverKeyPair.getPrivate();

            try (ServerSocket serverSocket = new ServerSocket(PORT);
                 Socket socket = serverSocket.accept();
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                 BufferedReader consoleInput = new BufferedReader(new InputStreamReader(System.in))) {

                System.out.println("Client connected.");

                // Send server public key to the client
                out.println(RSAUtils.publicKeyToString(serverPublicKey));
                System.out.println("Server public key sent to client.");

                // Receive client public key
                String clientPublicKeyEncoded = in.readLine();
                clientPublicKey = RSAUtils.stringToPublicKey(clientPublicKeyEncoded);

                // Receive and decrypt the AES key
                String encryptedSecretKeyEncoded = in.readLine();
                byte[] encryptedSecretKey = Base64.getDecoder().decode(encryptedSecretKeyEncoded);
                byte[] aesKeyBytes = RSAUtils.decrypt(serverPrivateKey, encryptedSecretKey);
                secretKey = new SecretKeySpec(aesKeyBytes, "AES");
                System.out.println("AES key received and decrypted.");

                // Create a thread to handle incoming messages from the client
                Thread clientHandler = new Thread(() -> {
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
                                    System.out.println("\nClient says: " + decryptedMessage);
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
                clientHandler.start();

                // Read messages from the console and send them to the client
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
