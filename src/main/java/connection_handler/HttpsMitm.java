package connection_handler;

import model.HttpRequestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import utils.SSLCertificateManager;
import utils.SocketsConnectionManager;

import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;


import static config.CertificateConfig.*;

public class HttpsMitm {
    private final SocketsConnectionManager connectionManager;
    private final SSLCertificateManager certificateManager;
    private final RequestResponseHandler requestResponseHandler;

    public HttpsMitm(ExecutorService pool, SocketsConnectionManager connectionManager, SSLCertificateManager certificateManager) {
        this.certificateManager = certificateManager;
        this.connectionManager = connectionManager;
        this.requestResponseHandler = new RequestResponseHandler(pool, false);
    }

    public void startMitm(Socket clientSocket, HttpRequestInfo requestInfo) {
        System.out.println(requestInfo.getRequest());

        SSLSocket clientSSLSocket = startClientHttpsConnection(clientSocket, requestInfo);
        SSLSocket serverSSLSocket = startServerHttpsConnection(clientSocket, requestInfo);

        if (serverSSLSocket == null || clientSSLSocket == null) {
            return;
        }

        requestResponseHandler.handleConnection(clientSSLSocket, serverSSLSocket);
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
}