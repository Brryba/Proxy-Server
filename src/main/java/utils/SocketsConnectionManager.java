package utils;

import java.io.IOException;
import java.net.Socket;

public class SocketsConnectionManager {
    public void shutDownConnections(Socket... sockets) {
        for (Socket socket : sockets) {
            try {
                socket.close();
            } catch (IOException _) {
            }
        }
    }
}
