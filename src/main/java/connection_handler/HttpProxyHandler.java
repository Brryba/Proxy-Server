package connection_handler;

import config.ProxyConfig;
import model.HttpRequestInfo;
import service.ResponseCacheService;
import utils.SocketsConnectionManager;

import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.ExecutorService;

public class HttpProxyHandler {
    private final ExecutorService pool;
    private final SocketsConnectionManager connectionManager;
    private String hostName;

    public HttpProxyHandler(ExecutorService pool, SocketsConnectionManager connectionManager) {
        this.pool = pool;
        this.connectionManager = connectionManager;
    }

    public void startHTTPConnection(Socket clientSocket, HttpRequestInfo requestInfo) {
        try {
            hostName = requestInfo.getHost();
            Socket httpSocket = new Socket(requestInfo.getHost(), requestInfo.getPort());
            String improvedRequest = logAndUpdateRequestInfo(requestInfo);
            httpSocket.getOutputStream().write(improvedRequest.getBytes(), 0, improvedRequest.length());

            pool.execute(() -> handleRequests(clientSocket, httpSocket));
            handleResponses(clientSocket, httpSocket);
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }

    private void handleRequests(Socket clientSocket, Socket httpSocket) {
        try {
            HttpRequestInfo request = new HttpRequestInfo();
            byte[] buffer = new byte[ProxyConfig.BUFFER_SIZE];
            while (true) {
                int bytesRead = clientSocket.getInputStream().read(buffer);
                if (bytesRead == -1) {
                    connectionManager.shutDownConnections(clientSocket, httpSocket);
                    break;
                }
                try {
                    request.setRequestData(buffer, bytesRead);
                } catch (IllegalArgumentException e) {
                    System.err.println(e.getMessage());
                    break;
                }
                if (!request.getMethod().equals("CONNECT")) {
                    String improvedRequest = logAndUpdateRequestInfo(request);
                    httpSocket.getOutputStream().write(improvedRequest.getBytes(), 0, improvedRequest.length());
                }
            }
        } catch (IOException _) {
            connectionManager.shutDownConnections(clientSocket, httpSocket);
        }
    }

    public void handleResponses(Socket clientSocket, Socket httpSocket) {
        try {
            byte[] buffer = new byte[ProxyConfig.BUFFER_SIZE];
            while (true) {
                int bytesRead = httpSocket.getInputStream().read(buffer);
                if (bytesRead == -1) {
                    connectionManager.shutDownConnections(clientSocket, httpSocket);
                    break;
                }
                logResponse(buffer, bytesRead);
                clientSocket.getOutputStream().write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            connectionManager.shutDownConnections(clientSocket, httpSocket);
        }
    }

    private void logResponse(byte[] bytes, int bytesRead) {
        String response = new String(bytes, 0, bytesRead);
        if (!response.startsWith("HTTP")) {
            System.out.println("\nResponse with no header form " + hostName + ", length: " + bytesRead);
            return;
        }

        int emptyLineIndex = response.indexOf("\r\n\r\n");
        System.out.println("Response from " + hostName + ":");
        ResponseCacheService.getInstance().cacheResponse(response);
        if (emptyLineIndex == -1) {
            System.out.println(response);
        } else {
            System.out.println(response.substring(0, emptyLineIndex));
        }
        System.out.println("\n");
    }

    private static String logAndUpdateRequestInfo(HttpRequestInfo request) {
        System.out.println("Original request: \n" + request.getRequest());
        String improvedRequest = request.getProxyModifiedRequest();
        System.out.println("Proxy-modified request: \n" + improvedRequest);
        return improvedRequest;
    }
}
