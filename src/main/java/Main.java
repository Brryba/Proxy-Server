import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {
    static ExecutorService pool = Executors.newCachedThreadPool();

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(54321, 50, InetAddress.getByName("127.0.0.1"))) {

            while (true) {
                Socket socket = serverSocket.accept();
                pool.execute(() -> new Runnable() {
                    static volatile boolean running = true;
                    public void run() {
                        createNewConnection(socket);
                    }
                });
            }
        } catch (IOException ex) {
            System.err.println(ex.getMessage());
        }
    }

    public static void createNewConnection(Socket clientSocket) {
        HTTPRequestInfo requestInfo = new HTTPRequestInfo();
        byte[] buffer = new byte[1024];
        try {
            int bytesRead = clientSocket.getInputStream().read(buffer);
            requestInfo.setRequestData(buffer, bytesRead);
            if (requestInfo.getProtocol().equals("HTTP") && !requestInfo.getMethod().equals("CONNECT")) {
                try {
                    Socket httpSocket = new Socket(requestInfo.getHost(), requestInfo.getPort());
                    String improvedRequest = logAndUpdateRequestInfo(requestInfo);
                    httpSocket.getOutputStream().write(improvedRequest.getBytes(), 0, improvedRequest.length());
                    pool.execute(() -> handleRequests(clientSocket, httpSocket));
                    pool.execute(() -> handleResponses(clientSocket, httpSocket));
                } catch (SocketException e) {
                    System.out.println("Server thread interrupted");
                }
            }
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }

    public static void handleRequests(Socket clientSocket, Socket httpSocket) {
        while (true) {
            HTTPRequestInfo request = new HTTPRequestInfo();
            byte[] buffer = new byte[1024];
            try {
                int bytesRead = clientSocket.getInputStream().read(buffer);
                if (bytesRead == -1) {
                    continue;
                }
                request.setRequestData(buffer, bytesRead);
                if (request.getProtocol().equals("HTTP") && !request.getMethod().equals("CONNECT")) {
                    String improvedRequest = logAndUpdateRequestInfo(request);
                    httpSocket.getOutputStream().write(improvedRequest.getBytes(), 0, improvedRequest.length());
                }
            } catch (SocketException socketException) {
                System.err.println("Connection was stopped");
            } catch (IOException e) {
                System.err.println("Wrong request Data: " + e.getMessage());
            }
        }
    }

    public static void handleResponses(Socket clientSocket, Socket httpSocket) {
        try {
            byte[] buffer = new byte[1024];
            while (true) {
                int bytesRead = httpSocket.getInputStream().read(buffer);
                if (bytesRead == -1) {
                    continue;
                }
                //WORK WITH RESPONSES HERE
                clientSocket.getOutputStream().write(buffer, 0, bytesRead);
            }
        } catch (SocketException e) {
            System.out.println("Connection was stopped");
        }
        catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }

    private static String logAndUpdateRequestInfo(HTTPRequestInfo request) {
        System.out.println(request.getRequest());
        String improvedRequest = request.getRequestWithPathUri();
        System.out.println(improvedRequest);
        return improvedRequest;
    }
}