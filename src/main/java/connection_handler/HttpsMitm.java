package connection_handler;

import config.ProxyConfig;
import model.HttpRequestInfo;
import utils.SocketsConnectionManager;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.ExecutorService;

public class HttpsMitm {
    private final ExecutorService pool;
    private final SocketsConnectionManager connectionManager;
    private String hostName;

    private enum Direction {
        REQUEST, RESPONSE
    }

    public HttpsMitm(ExecutorService pool, SocketsConnectionManager connectionManager) {
        this.pool = pool;
        this.connectionManager = connectionManager;
    }

    public void startMitm(Socket clientSocket, HttpRequestInfo requestInfo) {
        System.out.println(requestInfo.getRequest());
        this.hostName = requestInfo.getHost();

        try {
            Socket httpsSocket = new Socket(requestInfo.getHost(), requestInfo.getPort());
            final String answer = "HTTP/1.1 200 Connection Established\r\n\r\n";
            clientSocket.getOutputStream().write(answer.getBytes());
            clientSocket.getOutputStream().flush();
            startClientHttpsConnection(clientSocket, requestInfo);
            startServerHttpsConnection(clientSocket, requestInfo);

//            pool.execute(() -> handleTunnel(clientSocket, httpsSocket, HttpsTunnel.Direction.REQUEST));
//            handleTunnel(httpsSocket, clientSocket, HttpsTunnel.Direction.RESPONSE);
        } catch (IOException e) {
            System.err.println("HTTPS setup failed: " + e.getMessage());
        }
    }

    private void startServerHttpsConnection(Socket clientSocket, HttpRequestInfo requestInfo) {
        try {
            SSLSocket serverSocket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(requestInfo.getHost(), requestInfo.getPort());
            serverSocket.startHandshake();

//            byte[] buffer = new byte[ProxyConfig.BUFFER_SIZE];
//            int bytesRead = sslSocket.getInputStream().read(buffer);
//            System.out.println("Response by server");
//            System.out.println(new String(buffer, 0, bytesRead));
        } catch (IOException e) {
            connectionManager.shutDownConnections(clientSocket);
        }
    }

    private void startClientHttpsConnection(Socket clientPlainSocket, HttpRequestInfo requestInfo) {
        try {
            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket clientSslSocket = (SSLSocket)
                    sslSocketFactory.createSocket(clientPlainSocket,
                            clientPlainSocket.getInetAddress().getHostName(),
                            clientPlainSocket.getPort(), true);
            clientSslSocket.startHandshake();
            System.out.println("SSL handshake successful");
        } catch (IOException e) {
            System.err.println(e.getMessage());
            connectionManager.shutDownConnections(clientPlainSocket);
        }
    }
}
