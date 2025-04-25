import java.io.IOException;
import java.net.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {
    static int MAX_THREADS = 30;
    static int PORT = 54321;
    static String HOST = "127.0.0.1";
    static int BACKLOG = 10;

    static ExecutorService pool = Executors.newFixedThreadPool(MAX_THREADS);

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT, BACKLOG, InetAddress.getByName(HOST))) {
            while (true) {
                Socket socket = serverSocket.accept();
                pool.execute(() -> createNewConnection(socket));
            }
        } catch (IOException ex) {
            System.err.println(ex.getMessage());
        }
    }

    public static void createNewConnection(Socket clientSocket) {
        HTTPRequestInfo requestInfo = new HTTPRequestInfo();
        byte[] buffer = new byte[16384];
        try {
            int bytesRead = clientSocket.getInputStream().read(buffer);
            try {
                requestInfo.setRequestData(buffer, bytesRead);
            } catch (IllegalArgumentException e) {
                System.err.println(e.getMessage());
                return;
            }
            if (requestInfo.getProtocol().equals("HTTP") && !requestInfo.getMethod().equals("CONNECT")) {
                Socket httpSocket = new Socket(requestInfo.getHost(), requestInfo.getPort());
                String improvedRequest = logAndUpdateRequestInfo(requestInfo);
                httpSocket.getOutputStream().write(improvedRequest.getBytes(), 0, improvedRequest.length());

                pool.execute(() -> handleRequests(clientSocket, httpSocket));
                handleResponses(clientSocket, httpSocket);
            }
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }

    public static void handleRequests(Socket clientSocket, Socket httpSocket) {
        try {
            HTTPRequestInfo request = new HTTPRequestInfo();
            byte[] buffer = new byte[16384];
            while (true) {
                int bytesRead = clientSocket.getInputStream().read(buffer);
                if (bytesRead == -1) {
                    shutDownConnections(clientSocket, httpSocket);
                    break;
                }
                try {
                    request.setRequestData(buffer, bytesRead);
                } catch (IllegalArgumentException e) {
                    System.err.println(e.getMessage());
                    break;
                }
                if (request.getProtocol().equals("HTTP") && !request.getMethod().equals("CONNECT")) {
                    String improvedRequest = logAndUpdateRequestInfo(request);
                    httpSocket.getOutputStream().write(improvedRequest.getBytes(), 0, improvedRequest.length());
                }
            }
        } catch (IOException _) {
            shutDownConnections(clientSocket, httpSocket);
        }
    }

    public static void handleResponses(Socket clientSocket, Socket httpSocket) {
        try {
            byte[] buffer = new byte[16384];
            while (true) {
                int bytesRead = httpSocket.getInputStream().read(buffer);
                if (bytesRead == -1) {
                    shutDownConnections(clientSocket, httpSocket);
                    break;
                }
                logResponse(buffer, bytesRead);
                clientSocket.getOutputStream().write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            shutDownConnections(clientSocket, httpSocket);
        }
    }

    private static void logResponse(byte[] bytes, int bytesRead) {
        String response = new String(bytes, 0, bytesRead);
        if (!response.startsWith("HTTP")) {
            System.out.println("\nResponse with no header, length: " + bytesRead);
            return;
        }

        int emptyLineIndex = response.indexOf("\r\n\r\n");
        System.out.println("Response:");
        if (emptyLineIndex == -1) {
            System.out.println(response);
        } else {
            System.out.println(response.substring(0, emptyLineIndex));
        }
        System.out.println("\n");
    }

    private static void shutDownConnections(Socket clientSocket, Socket httpSocket) {
        try {
            clientSocket.close();
            httpSocket.close();
        } catch (IOException _) {
        }
    }

    private static String logAndUpdateRequestInfo(HTTPRequestInfo request) {
        System.out.println("Original request: \n" + request.getRequest());
        String improvedRequest = request.getProxyModifiedRequest();
        System.out.println("Proxy-modified request: \n" + improvedRequest);
        return improvedRequest;
    }
}