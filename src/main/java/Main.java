import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(12345, 50, InetAddress.getByName("127.0.0.1"));
             ExecutorService executorService = Executors.newCachedThreadPool()) {

            while (true) {
                Socket socket = serverSocket.accept();

                executorService.execute(() -> handleRequest(socket));
            }
        } catch (IOException ex) {
            System.err.println(ex.getMessage());
        }
    }

    public static void handleRequest(Socket socket) {
        HTTPRequestInfo request = new HTTPRequestInfo();
        byte[] buffer = new byte[1024];
        try {
            int bytesRead = socket.getInputStream().read(buffer);
            request.setRequestData(buffer, bytesRead);
            if (request.getProtocol().equals("HTTP") && !request.getMethod().equals("CONNECT")) {
                processHTTPConnection(socket, request);
            }
        } catch (IOException e) {
            System.err.println("Wrong request Data: " + e.getMessage());
        }
    }

    public static void processHTTPConnection(Socket clientSocket, HTTPRequestInfo request) throws IOException {
        try (Socket httpSocket = new Socket(request.getHost(), request.getPort())) {
            byte[] buffer = new byte[1024];
            String improvedRequest = request.getRequest().replace(request.getAbsoluteUri(), request.getPathUri());
            System.out.println(improvedRequest);
            httpSocket.getOutputStream().write(improvedRequest.getBytes(), 0, improvedRequest.length());
            while (true) {
                int bytesRead = httpSocket.getInputStream().read(buffer);
                if (bytesRead == -1) {
                    continue;
                }
                clientSocket.getOutputStream().write(buffer, 0, bytesRead);
            }
        } catch (SocketException _) {}
    }



//
//
//
//                Socket httpSocket = new Socket(InetAddress.getByName("live.legendy.by"), 8000);
//
//                new Thread(() -> {
//                    try {
//                        byte[] buffer2 = new byte[111111];
//                        int bytesRead2;
//                        while (true) {
//                            bytesRead2 = httpSocket.getInputStream().read(buffer2);
//                            System.out.println("Server response");
//                            String output = new String(buffer2, 0, bytesRead2);
//                            //System.out.println(output);
//                            socket.getOutputStream().write(buffer2, 0, bytesRead2);
//                            //System.out.println(output);
//                        }
//                    } catch (Exception e){}
//                }).start();
//
//                new Thread(() -> {
//                    try {byte[] buffer = new byte[111111];
//                        int bytesRead = socket.getInputStream().read(buffer);
//                        System.out.println("Server request");
//                        String input = new String(buffer, 0, bytesRead);
//                        System.out.println(input);
//                        input = input.replace("http://live.legendy.by:8000/legendyfm",
//                                "/legendyfm");
//                        httpSocket.getOutputStream().write(input.getBytes());
//                        httpSocket.getOutputStream().flush();
//                    } catch (IOException e) {
//                        throw new RuntimeException(e);
//                    }
//                }).start();
//            }
//        } catch (Exception e) {
//            System.err.println(e.getMessage());
//        }
//    }
}