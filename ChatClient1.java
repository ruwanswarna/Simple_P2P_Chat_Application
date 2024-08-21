import java.io.*;
import java.net.*;

public class ChatClient1 {
    private static final String SERVER_ADDRESS = "localhost"; // or the server's IP address
    private static final int SERVER_PORT = 12345;

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader consoleInput = new BufferedReader(new InputStreamReader(System.in))) {

            System.out.println("Connected to friend's app.");

            // Create a thread to handle incoming messages from the server
            Thread serverHandler = new Thread(() -> {
                String message;
				
                try {
					System.out.print("Say something:");
                    while ((message = in.readLine()) != null) {
                        System.out.println("\nFriend Says: " + message);
						System.out.print("Say something:");
                    }
					
                } catch (IOException e) {
                    System.out.println("Connection lost.");
                }
				
            });
            serverHandler.start();

            // Read messages from the console and send them to the server
            String userInput;
            while ((userInput = consoleInput.readLine()) != null) {
                out.println(userInput);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
