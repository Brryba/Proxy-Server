package connection_handler;

import config.ProxyConfig;
import model.HttpRequestInfo;
import utils.SocketsConnectionManager;

import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.ExecutorService;

public class HttpsTunnel {
    private final ExecutorService pool;
    private final SocketsConnectionManager connectionManager;
    private String hostName;

    private enum Direction {
        REQUEST, RESPONSE
    }

    public HttpsTunnel(ExecutorService pool, SocketsConnectionManager connectionManager) {
        this.pool = pool;
        this.connectionManager = connectionManager;
    }

    public void startTunnel(Socket clientSocket, HttpRequestInfo requestInfo) {
        System.out.println(requestInfo.getRequest());
        this.hostName = requestInfo.getHost();

        try {
            Socket httpsSocket = new Socket(requestInfo.getHost(), requestInfo.getPort());
            final String answer = "HTTP/1.1 200 Connection Established\r\n\r\n";
            clientSocket.getOutputStream().write(answer.getBytes());
            clientSocket.getOutputStream().flush();

            pool.execute(() -> handleTunnel(clientSocket, httpsSocket, Direction.REQUEST));
            handleTunnel(httpsSocket, clientSocket, Direction.RESPONSE);
        } catch (IOException e) {
            System.err.println("HTTPS setup failed: " + e.getMessage());
        }
    }

    private void handleTunnel(Socket source, Socket destination, Direction direction) {
        byte[] buf = new byte[ProxyConfig.BUFFER_SIZE];
        try {
            while (true) {
                int bytesRead = source.getInputStream().read(buf);
                if (bytesRead == -1) {
                    connectionManager.shutDownConnections(source, destination);
                    logClosed(direction);
                    break;
                }

                destination.getOutputStream().write(buf, 0, bytesRead);
                destination.getOutputStream().flush();

                logTransfer(direction);
            }
        } catch (IOException e) {
            logException(direction, e);
        } finally {
            connectionManager.shutDownConnections(source, destination);
            logClosed(direction);
        }
    }

    private void logTransfer(Direction direction) {
        System.out.println(direction.equals(Direction.REQUEST)
                ? "Client -> " + hostName + " encrypted HTTPS request"
                : hostName + " -> Client encrypted HTTPS response");
    }

    private void logClosed(Direction direction) {
        System.out.println("\nHTTPS Connection " +
                (direction.equals(Direction.REQUEST) ? "closed by client\n" : "closed by " + hostName));
    }

    private void logException(Direction direction, Exception e) {
        System.err.println(direction.equals(Direction.REQUEST)
                ? "Client -> " + hostName + " error: " + e.getMessage()
                : hostName + " -> Client error: " + e.getMessage());
    }
}
