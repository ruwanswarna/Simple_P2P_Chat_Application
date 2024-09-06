import java.io.*;
import java.net.*;
import java.util.Scanner;
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
    private static String SERVER_ADDRESS = "localhost";
    private static final int PORT = 12345;
    private static SecretKey secretKey;
    private static PublicKey serverPublicKey;
    private static PrivateKey clientPrivateKey;
    private static PublicKey clientPublicKey;

     public static boolean isValidIP(String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);
            return address.getHostAddress().equals(ip) && ip.matches("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b");
        } catch (UnknownHostException e) {
            return false;
        }
    }

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter peer ip address: ");
        SERVER_ADDRESS = scanner.nextLine();
        System.out.println(SERVER_ADDRESS);
        if(SERVER_ADDRESS == ""){
            SERVER_ADDRESS = "127.0.0.1";
        }
        if(!isValidIP(SERVER_ADDRESS)){
            System.out.println("Invalid IP address. Exiting......");
            return;
        }
        System.out.println("_______________________________________________________________");
        try {
            // Generate RSA keys for the peer1
            KeyPair clientKeyPair = RSAUtils.generateKeyPair();
            clientPublicKey = clientKeyPair.getPublic();
            clientPrivateKey = clientKeyPair.getPrivate();

            try (Socket socket = new Socket(SERVER_ADDRESS, PORT);
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                 BufferedReader consoleInput = new BufferedReader(new InputStreamReader(System.in))) {

                // Send peer1 public key to peer2
                out.println(RSAUtils.publicKeyToString(clientPublicKey));
                System.out.println("RSA public key sent to peer2.");

                // Receive peer2 public key
                String serverPublicKeyEncoded = in.readLine();
                serverPublicKey = RSAUtils.stringToPublicKey(serverPublicKeyEncoded);

                // Generate a new AES key
                secretKey = AESUtils.generateKey();

                // Encrypt the AES key with peer2's public key and send it
                byte[] encryptedSecretKey = RSAUtils.encrypt(serverPublicKey, secretKey.getEncoded());
                out.println(Base64.getEncoder().encodeToString(encryptedSecretKey));
                System.out.println("AES key sent to peer2.");
                System.out.println("_________________________________________________________");

                // handle incoming messages from the peer2
                Thread serverHandler = new Thread(() -> {
                    String message;

                    System.out.print("\nSay something: ");
                    try {
                        
                        while ((message = in.readLine()) != null) {
                            // Split received message into encrypted part and hash part
                            String[] parts = message.split("::");
                            if (parts.length == 2) {
                                String encryptedMessage = parts[0];
                                String receivedHash = parts[1];

                                // Decrypt the message
                                String decryptedMessage = AESUtils.decrypt(encryptedMessage, secretKey);

                                // Verify the integrity
                                if (HashUtils.verifyHash(decryptedMessage, receivedHash)) {
                                    System.out.println("\nFriend says: " + decryptedMessage);
                                } else {
                                    System.out.println("\nMessage integrity check failed.");
                                }
                                System.out.print("\nSay something: ");
                            } else {
                                System.out.println("Invalid message format.");
                            }
                        }

                    } catch (Exception e) {

                        System.out.println("Connection lost.");
                    }
                });
                serverHandler.start();

                //  read from console and send messages to the peer2
                String userInput;
                while ((userInput = consoleInput.readLine()) != null) {
                    // Encrypt the message
                    String encryptedMessage = AESUtils.encrypt(userInput, secretKey);

                    // Compute the hash of the message
                    String hash = HashUtils.computeHash(userInput);

                    // Send the encrypted message and hash separated by "::"
                    out.println(encryptedMessage + "::" + hash);

                    System.out.print("\nSay something: ");

                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
