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
import java.net.SocketException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


import static config.CertificateConfig.*;

public class HttpsMitm {
    private final ExecutorService pool;
    private final SocketsConnectionManager connectionManager;
    private final SSLCertificateManager certificateManager;
    private final ResponseCacheService responseCacheService;
    private final Deque<String> requests;

    public HttpsMitm(ExecutorService pool, SocketsConnectionManager connectionManager, SSLCertificateManager certificateManager) {
        this.certificateManager = certificateManager;
        this.pool = pool;
        this.connectionManager = connectionManager;
    }

    {
        responseCacheService = ResponseCacheService.getInstance();
        requests = new LinkedList<>();
    }

    public void startMitm(Socket clientSocket, HttpRequestInfo requestInfo) {
        System.out.println(requestInfo.getRequest());

        SSLSocket clientSSLSocket = startClientHttpsConnection(clientSocket, requestInfo);
        SSLSocket serverSSLSocket = startServerHttpsConnection(clientSocket, requestInfo);

        if (serverSSLSocket == null || clientSSLSocket == null) {
            return;
        }

        pool.execute(() -> handleClientToServer(clientSSLSocket, serverSSLSocket));
        handleServerToClient(clientSSLSocket, serverSSLSocket);
    }

    private void handleClientToServer(SSLSocket clientSSLSocket, SSLSocket serverSSLSocket) {
        try {
            while (true) {
                byte[] buf = new byte[ProxyConfig.BUFFER_SIZE];
                int bytesRead = clientSSLSocket.getInputStream().read(buf);
                try {
                    HttpRequestInfo r = new HttpRequestInfo();
                    r.setRequestData(buf, bytesRead);
                    requests.addFirst(r.getHost() + r.getPathUri());
                    System.out.println(r.getRequest());
                } catch (Exception _) {
                }
                if (bytesRead == -1) {
                    connectionManager.shutDownConnections(clientSSLSocket, serverSSLSocket);
                    break;
                }

                if (responseCacheService.containsResponse(requests.getLast())) {
                    writeCachedRequestToClient(clientSSLSocket);
                    System.out.println(requests.getLast() + " CACHED");
                    requests.removeLast();
                } else {
                    serverSSLSocket.getOutputStream().write(buf, 0, bytesRead);
                    serverSSLSocket.getOutputStream().flush();
                }
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private void handleServerToClient(SSLSocket clientSSLSocket, SSLSocket serverSSLSocket) {
        try {
            ByteArrayOutputStream multiPacketsBuffer = null;
            int contentLengthRemained = -1;
            boolean isChunkedResponse = false;

            while (true) {
                byte[] buf = new byte[ProxyConfig.BUFFER_SIZE];
                int bytesRead = serverSSLSocket.getInputStream().read(buf);
                if (bytesRead == -1) {
                    connectionManager.shutDownConnections(clientSSLSocket, serverSSLSocket);
                    break;
                }

                clientSSLSocket.getOutputStream().write(buf, 0, bytesRead);
                clientSSLSocket.getOutputStream().flush();

                if (contentLengthRemained > -1) {
                    if (multiPacketsBuffer == null) {
                        multiPacketsBuffer = new ByteArrayOutputStream();
                    }
                    contentLengthRemained = cacheResponseWithContentLength(buf, bytesRead, contentLengthRemained, multiPacketsBuffer);
                    continue;
                }

                String beginning = new String(buf, 0, 5);
                if (contentLengthRemained == -1 && !isChunkedResponse && !beginning.equals("HTTP/")) {
                    continue;
                }

                logResponse(new String(buf, 0, bytesRead), requests.getLast());

                contentLengthRemained = getContentLength(buf, bytesRead);

                if (contentLengthRemained > 0) {
                    multiPacketsBuffer = new ByteArrayOutputStream();
                    contentLengthRemained = cacheResponseWithContentLength(buf, bytesRead,
                            contentLengthRemained + getHeadersLength(buf, bytesRead), multiPacketsBuffer);
                } else {
                    if (!isChunkedResponse) {
                        multiPacketsBuffer = null;
                        isChunkedResponse = isChunked(buf, bytesRead);
                        if (isChunkedResponse) {
                            multiPacketsBuffer = new ByteArrayOutputStream();
                        }
                    }

                    isChunkedResponse = cacheResponseAndSetChunked(buf, bytesRead, isChunkedResponse, multiPacketsBuffer);
                }
            }
        } catch (SocketException _) {

        }
        catch (Exception e) {
            e.printStackTrace();
            System.err.println(e.getMessage());
        }
    }

    private void writeCachedRequestToClient(SSLSocket clientSSLSocket) {
        byte[] serviceResponse = responseCacheService.getResponse(requests.getLast());
        int remainedLength = serviceResponse.length, bytesRead = 0;
        final int TLS_MAX_LENGTH = 16384;
        try {
            do {
                if (remainedLength > TLS_MAX_LENGTH) {
                    byte[] temp = Arrays.copyOfRange(serviceResponse, bytesRead, bytesRead + TLS_MAX_LENGTH);
                    bytesRead += TLS_MAX_LENGTH;
                    remainedLength -= TLS_MAX_LENGTH;
                    clientSSLSocket.getOutputStream().write(temp, 0, TLS_MAX_LENGTH);
                    clientSSLSocket.getOutputStream().flush();
                } else {
                    clientSSLSocket.getOutputStream().write(serviceResponse, bytesRead, remainedLength);
                    clientSSLSocket.getOutputStream().flush();
                    remainedLength = 0;
                }
            } while (remainedLength > 0);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private int cacheResponseWithContentLength(byte[] buf, int bytesRead, int contentLengthRemained, ByteArrayOutputStream contentBuffer) {
        int bytesToWrite = Math.min(bytesRead, contentLengthRemained);
        contentBuffer.write(buf, 0, bytesToWrite);

        if (bytesToWrite >= contentLengthRemained) {
            String requestName = requests.removeLast();
            CompletableFuture.runAsync(() ->
                    responseCacheService.cacheResponse(requestName, contentBuffer.toByteArray()));
            return -1;
        }
        return contentLengthRemained - bytesToWrite;
    }

    private int getHeadersLength(byte[] response, int length) {
        String responseStr = new String(response, 0, Math.min(length, 2048));
        return responseStr.indexOf("\r\n\r\n") + 4;
    }

    private int getContentLength(byte[] response, int length) {
        String headers = new String(response, 0, Math.min(length, 2048));
        Pattern pattern = Pattern.compile("Content-Length:\\s*(\\d+)");
        Matcher matcher = pattern.matcher(headers);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group(1));
        }
        return -1;
    }

    private boolean cacheResponseAndSetChunked(byte[] response, int responseLength, boolean isChunked, ByteArrayOutputStream chunkedBuffer) {
        if (isChunked) {
            chunkedBuffer.write(response, 0, responseLength);

            if (isEndOfChunked(response, responseLength)) {
                byte[] fullData = chunkedBuffer.toByteArray();
                String requestName = requests.removeLast();
                CompletableFuture.runAsync(() ->
                        responseCacheService.cacheResponse(requestName, fullData));
                return false;
            }
        } else {
            byte[] finalResponseData = Arrays.copyOf(response, responseLength);
            String requestName = requests.removeLast();
            CompletableFuture.runAsync(() ->
                    responseCacheService.cacheResponse(requestName, finalResponseData));
            return false;
        }
        return true;
    }

    private boolean isChunked(byte[] response, int length) {
        String headers = new String(response, 0, Math.min(length, 2048));
        return headers.contains("Transfer-Encoding: chunked");
    }

    private boolean isEndOfChunked(byte[] data, int dataLength) {
        if (dataLength < 5) return false;
        int start = Math.max(0, dataLength - 7);
        String tail = new String(data, start, dataLength - start);
        return tail.contains("0\r\n\r\n");
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

    private void logResponse(String response, String uri) {
        if (!response.startsWith("HTTP")) {
            return;
        }
        int emptyLineIndex = response.indexOf("\r\n\r\n");
        System.out.println("Response from " + uri + ":");
        if (emptyLineIndex == -1) {
            System.out.println(response);
        } else {
            System.out.println(response.substring(0, emptyLineIndex));
        }
        System.out.println("\n");
    }
}