import java.io.*;
import java.net.*;

public class ChatClient2 {
    private static final int PORT = 12345;

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server started. Waiting for a connection...");
            try (Socket clientSocket = serverSocket.accept();
                 BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                 PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                 BufferedReader consoleInput = new BufferedReader(new InputStreamReader(System.in))) {

                System.out.println("Connected to friend's app.");

                // Create a thread to handle incoming messages from the client
                Thread clientHandler = new Thread(() -> {
                    String message;
					
                    try {
						System.out.print("Say something:");
                        while ((message = in.readLine()) != null) {
                            System.out.println("\nFriend says: " + message);
							System.out.print("Say something:");
                        }
						
                    } catch (IOException e) {
                        System.out.println("Connection lost.");
                    }
					
                });
                clientHandler.start();

                // Read messages from the console and send them to the client
                String userInput;
                while ((userInput = consoleInput.readLine()) != null) {
                    out.println(userInput);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
