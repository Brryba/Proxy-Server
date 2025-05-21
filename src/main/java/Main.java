import config.ProxyConfig;
import connection_handler.HttpProxyHandler;
import connection_handler.HttpsMitm;
import connection_handler.HttpsTunnel;
import model.HttpRequestInfo;
import service.BlackListChecker;
import utils.SSLCertificateManager;
import utils.SocketsConnectionManager;

import java.io.IOException;
import java.net.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {

    private static final ExecutorService pool = Executors.newCachedThreadPool();
    private static final ProxyConfig proxyConfig = new ProxyConfig();

    public static void main(String[] args) {
        proxyConfig.initialize();
        try (ServerSocket serverSocket = new ServerSocket(ProxyConfig.PORT, ProxyConfig.BACKLOG, InetAddress.getByName(ProxyConfig.HOST))) {
            while (true) {
                Socket socket = serverSocket.accept();
                pool.execute(() -> createNewConnection(socket));
            }
        } catch (IOException ex) {
            System.err.println(ex.getMessage());
        }
    }

    private static void createNewConnection(Socket clientSocket) {
        HttpRequestInfo requestInfo = new HttpRequestInfo();
        byte[] buffer = new byte[ProxyConfig.BUFFER_SIZE];
        try {
            int bytesRead = clientSocket.getInputStream().read(buffer);
            try {
                requestInfo.setRequestData(buffer, bytesRead);
            } catch (IllegalArgumentException e) {
                System.err.println(e.getMessage());
                return;
            }
            System.out.println(requestInfo.getRequest());
            if (BlackListChecker.isBlackListed(clientSocket, requestInfo)) return;
            if (requestInfo.getProtocol().equals("HTTP") && !requestInfo.getMethod().equals("CONNECT")) {
                HttpProxyHandler tunnel = new HttpProxyHandler(pool, new SocketsConnectionManager());
                tunnel.startHTTPConnection(clientSocket, requestInfo);
            } else if (requestInfo.getMethod().equals("CONNECT")) {
                if (ProxyConfig.httpsMode == ProxyConfig.HttpsMode.HTTPS_TUNNEL) {
                    HttpsTunnel tunnel = new HttpsTunnel(pool, new SocketsConnectionManager());
                    tunnel.startTunnel(clientSocket, requestInfo);
                } else {
                    HttpsMitm mitmProxy = new HttpsMitm(pool, new SocketsConnectionManager(), new SSLCertificateManager());
                    mitmProxy.startMitm(clientSocket, requestInfo);
                }
            }
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }
}