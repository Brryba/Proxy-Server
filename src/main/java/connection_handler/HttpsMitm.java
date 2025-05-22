package connection_handler;

import config.ProxyConfig;
import model.HttpRequestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import service.ResponseCacheService;
import utils.SSLCertificateManager;
import utils.SocketsConnectionManager;

import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;


import static config.CertificateConfig.*;

public class HttpsMitm {
    private final ExecutorService pool;
    private final SocketsConnectionManager connectionManager;
    private final SSLCertificateManager certificateManager;
    private final ResponseCacheService responseCacheService;
    private String hostName;
    private final Deque<String> requests = new ArrayDeque<>();

    public HttpsMitm(ExecutorService pool, SocketsConnectionManager connectionManager, SSLCertificateManager certificateManager) {
        this.certificateManager = certificateManager;
        this.pool = pool;
        this.connectionManager = connectionManager;
    }

    {
        responseCacheService = ResponseCacheService.getInstance();
    }

    public void startMitm(Socket clientSocket, HttpRequestInfo requestInfo) {
        System.out.println(requestInfo.getRequest());
        this.hostName = requestInfo.getHost();

        SSLSocket clientSSLSocket = startClientHttpsConnection(clientSocket, requestInfo);
        SSLSocket serverSSLSocket = startServerHttpsConnection(clientSocket, requestInfo);

        if (serverSSLSocket == null || clientSSLSocket == null) {
            return;
        }

        pool.execute(() -> {
            try {
                while (true) {
                    byte[] buf = new byte[ProxyConfig.BUFFER_SIZE];
                    int bytesRead = clientSSLSocket.getInputStream().read(buf);
                    HttpRequestInfo request = new HttpRequestInfo();
                    request.setRequestData(buf, bytesRead);
                    System.out.println(requestInfo.getRequest());
                    requests.addFirst(request.getHost() + request.getPathUri());
                    if (bytesRead == -1) {
                        connectionManager.shutDownConnections(clientSSLSocket, serverSSLSocket);
                        break;
                    }
                    System.out.println(new String(buf, 0, bytesRead));
                    serverSSLSocket.getOutputStream().write(buf, 0, bytesRead);
                    serverSSLSocket.getOutputStream().flush();
                }
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        });

        try {
            byte[] responseData;
            while (true) {
                byte[] buf = new byte[ProxyConfig.BUFFER_SIZE];
                int bytesRead = serverSSLSocket.getInputStream().read(buf);
                if (bytesRead == -1) {
                    connectionManager.shutDownConnections(clientSSLSocket, serverSSLSocket);
                    break;
                }

                logResponse(new String(buf, 0, bytesRead));

                responseData = Arrays.copyOf(buf, bytesRead);
                byte[] finalResponseData = responseData;
                if (!isChunked(buf, bytesRead)) {
                    CompletableFuture.runAsync(() -> responseCacheService.cacheResponse(requests.removeLast(), finalResponseData));
                }

                clientSSLSocket.getOutputStream().write(buf, 0, bytesRead);
                clientSSLSocket.getOutputStream().flush();
//                byte[] mockResponse = responseCacheService.getResponse("www.mirostat.by/");
//                clientSSLSocket.getOutputStream().write(mockResponse, 0, mockResponse.length);
//                clientSSLSocket.getOutputStream().flush();
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    private boolean isChunked(byte[] response, int length) {
        String headers = new String(response, 0, Math.min(length, 2048));
        return headers.contains("Transfer-Encoding: chunked");
    }

    private SSLSocket startServerHttpsConnection(Socket clientSocket, HttpRequestInfo requestInfo) {
        try {
            SSLSocket serverSocket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(requestInfo.getHost(), requestInfo.getPort());
            serverSocket.startHandshake();
            return serverSocket;
        } catch (IOException e) {
            connectionManager.shutDownConnections(clientSocket);
        }
        return null;
    }


    private SSLSocket startClientHttpsConnection(Socket clientPlainSocket, HttpRequestInfo requestInfo) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyStore caCertificateKeyStore = certificateManager.loadKeystore();

            X509Certificate rootCertificate = (X509Certificate) caCertificateKeyStore.getCertificate(ALIAS);
            PrivateKey privateKey = (PrivateKey) caCertificateKeyStore.getKey(ALIAS, PASSWORD.toCharArray());
            PublicKey publicKey = rootCertificate.getPublicKey();
            KeyPair rootCertificateKeyPair = new KeyPair(publicKey, privateKey);

            KeyPair issuedCertKeyPair = certificateManager.generateIssuedKeyPair();
            X509Certificate issuedCert = certificateManager.createIssuedCertificate(rootCertificate, requestInfo, rootCertificateKeyPair,
                    issuedCertKeyPair);

            respondToClient200(clientPlainSocket);
            return startSSLSocket(requestInfo, issuedCertKeyPair,
                    issuedCert, rootCertificate, clientPlainSocket);
        } catch (
                Exception e) {
            System.err.println(e.getMessage());
            connectionManager.shutDownConnections(clientPlainSocket);
            return null;
        }
    }

    public void respondToClient200(Socket clientSocket) throws Exception {
        final String answer = "HTTP/1.1 200 Connection Established\r\n\r\n";
        clientSocket.getOutputStream().write(answer.getBytes());
        clientSocket.getOutputStream().flush();
    }

    public SSLSocket startSSLSocket(HttpRequestInfo requestInfo,
                                    KeyPair issuedCertKeyPair, X509Certificate issuedCert, X509Certificate rootCertificate,
                                    Socket clientPlainSocket) throws Exception {
        SSLContext sslContext = certificateManager.getSSLContext(requestInfo, issuedCertKeyPair, issuedCert, rootCertificate);
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        SSLSocket clientSslSocket = (SSLSocket)
                sslSocketFactory.createSocket(clientPlainSocket,
                        clientPlainSocket.getInetAddress().getHostName(),
                        clientPlainSocket.getPort(), true);

        clientSslSocket.setUseClientMode(false);
        clientSslSocket.startHandshake();
        return clientSslSocket;
    }

    private void logResponse(String response) {
        if (!response.startsWith("HTTP")) {
            return;
        }
        int emptyLineIndex = response.indexOf("\r\n\r\n");
        System.out.println("Response from " + hostName + ":");
        if (emptyLineIndex == -1) {
            System.out.println(response);
        } else {
            System.out.println(response.substring(0, emptyLineIndex));
        }
        System.out.println("\n");
    }
}
