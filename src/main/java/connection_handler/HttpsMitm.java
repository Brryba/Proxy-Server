package connection_handler;

import config.ProxyConfig;
import model.HttpRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import utils.SocketsConnectionManager;

import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.concurrent.ExecutorService;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

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
                    System.out.println(new String(buf, 0, bytesRead));
                    if (bytesRead == -1) {
                        connectionManager.shutDownConnections(clientSSLSocket, serverSSLSocket);
                        break;
                    }

                    serverSSLSocket.getOutputStream().write(buf, 0, bytesRead);
                    serverSSLSocket.getOutputStream().flush();
                }
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        });

        try {
            while (true) {
                byte[] buf = new byte[ProxyConfig.BUFFER_SIZE];
                int bytesRead = serverSSLSocket.getInputStream().read(buf);
                if (bytesRead == -1) {
                    connectionManager.shutDownConnections(clientSSLSocket, serverSSLSocket);
                    break;
                }

                clientSSLSocket.getOutputStream().write(buf, 0, bytesRead);
                clientSSLSocket.getOutputStream().flush();
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private SSLSocket startServerHttpsConnection(Socket clientSocket, HttpRequestInfo requestInfo) {
        try {
            SSLSocket serverSocket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(requestInfo.getHost(), requestInfo.getPort());
            serverSocket.startHandshake();
            return serverSocket;
//            byte[] buffer = new byte[ProxyConfig.BUFFER_SIZE];
//            int bytesRead = sslSocket.getInputStream().read(buffer);
//            System.out.println("Response by server");
//            System.out.println(new String(buffer, 0, bytesRead));
        } catch (IOException e) {
            connectionManager.shutDownConnections(clientSocket);
        }
        return null;
    }

    private SSLSocket startClientHttpsConnection(Socket clientPlainSocket, HttpRequestInfo requestInfo) {
        try {
            File file = new File("D:\\java-projects\\certificates\\Brazgunou_CA.jks");
            InputStream is = new FileInputStream(file);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            String password = "Darkthrone";
            keystore.load(is, password.toCharArray());


            PrivateKey privateKey = (PrivateKey) keystore.getKey("brazgunou ca", password.toCharArray());


            Enumeration<String> enumeration = keystore.aliases();
            String alias = enumeration.nextElement();
            System.out.println("alias name: " + alias);

            X509Certificate rootCertificate = (X509Certificate) keystore.getCertificate(alias);
            PublicKey publicKey = rootCertificate.getPublicKey();
            KeyPair rootCertificateKeyPair = new KeyPair(publicKey, privateKey);
            X509Certificate rootCert = (X509Certificate) keystore.getCertificate("Brazgunou CA");
            X509Certificate issuedCert;

            try {
                Security.addProvider(new BouncyCastleProvider());
                final String BC_PROVIDER = "BC";
                final String KEY_ALGORITHM = "RSA";
                final String SIGNATURE_ALGORITHM = "SHA256withRSA";

                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
                keyPairGenerator.initialize(2048);

                Calendar calendar = Calendar.getInstance();
                calendar.add(Calendar.DATE, -1);
                Date startDate = calendar.getTime();

                calendar.add(Calendar.YEAR, 1);
                Date endDate = calendar.getTime();

                X500Name issuedCertSubject = new X500Name("CN=" + alias);
                BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
                KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();

                X500Name currentCertSubject = new X500Name("CN=" + requestInfo.getHost());
                PKCS10CertificationRequestBuilder p10Builder = new
                        JcaPKCS10CertificationRequestBuilder(currentCertSubject, issuedCertKeyPair.getPublic());
                JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);

                ContentSigner csrContentSigner = csrBuilder.build(rootCertificateKeyPair.getPrivate());
                PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

                X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(issuedCertSubject,
                        issuedCertSerialNum,
                        startDate,
                        endDate,
                        csr.getSubject(),
                        csr.getSubjectPublicKeyInfo());

                JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

                issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

                issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                        issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert));
                issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                        issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

                issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature
                        | KeyUsage.keyEncipherment));

                issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[]{
                        new GeneralName(GeneralName.dNSName, requestInfo.getHost())
                }));

                X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
                issuedCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);

                // Verify the issued cert signature against the root (issuer) cert
                issuedCert.verify(rootCertificate.getPublicKey(), BC_PROVIDER);

                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(null, null);

                keyStore.setKeyEntry(
                        requestInfo.getHost(),
                        issuedCertKeyPair.getPrivate(),
                        "Darkthrone".toCharArray(),
                        new Certificate[]{issuedCert, rootCertificate}
                );

                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(keyStore, "Darkthrone".toCharArray());

// Create SSLContext
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(
                        kmf.getKeyManagers(),  // Your generated cert + key
                        null,                  // No custom trust manager
                        new SecureRandom()
                );


                final String answer = "HTTP/1.1 200 Connection Established\r\n\r\n";
                clientPlainSocket.getOutputStream().write(answer.getBytes());
                clientPlainSocket.getOutputStream().flush();
                InputStream in = clientPlainSocket.getInputStream();
                while (in.available() > 0) in.read();


                SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
                SSLSocket clientSslSocket = (SSLSocket)
                        sslSocketFactory.createSocket(clientPlainSocket,
                                clientPlainSocket.getInetAddress().getHostName(),
                                clientPlainSocket.getPort(), true);

                clientSslSocket.setUseClientMode(false);
                clientSslSocket.startHandshake();
                System.out.println("SSL handshake successful");
                return clientSslSocket;

            } catch (Exception ex) {
                ex.printStackTrace();
                return null;
            }
        } catch (
                Exception e) {
            System.err.println(e.getMessage());
            connectionManager.shutDownConnections(clientPlainSocket);
            return null;
        }
    }

    static void writeCertToFileBase64Encoded(Certificate certificate, String fileName) throws Exception {
        FileOutputStream certificateOut = new FileOutputStream(fileName);
        certificateOut.write("-----BEGIN CERTIFICATE-----".getBytes());
        certificateOut.write(Base64.encode(certificate.getEncoded()));
        certificateOut.write("-----END CERTIFICATE-----".getBytes());
        certificateOut.close();
    }

    static void exportKeyPairToKeystoreFile(KeyPair keyPair, Certificate certificate, String alias, String fileName, String storeType, String storePass) throws Exception {
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, "BC");
        sslKeyStore.load(null, null);
        sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(), null, new Certificate[]{certificate});
        FileOutputStream keyStoreOs = new FileOutputStream(fileName);
        sslKeyStore.store(keyStoreOs, storePass.toCharArray());
    }
}
