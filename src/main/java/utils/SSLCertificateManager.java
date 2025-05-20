package utils;

import model.HttpRequestInfo;
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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import static config.CertificateConfig.*;
import static config.CertificateConfig.PASSWORD;

public class SSLCertificateManager {
    public KeyStore loadKeystore() throws Exception {
        try {
            File file = new File(CA_PATH);
            InputStream is = new FileInputStream(file);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, PASSWORD.toCharArray());
            return keystore;
        } catch (FileNotFoundException e) {
            System.err.println("File with certificate ( " + CA_PATH + ") was not found in program directory");
            throw e;
        }
    }

    public X509Certificate createIssuedCertificate(X509Certificate rootCertificate,
                                                    HttpRequestInfo requestInfo, KeyPair rootCertificateKeyPair,
                                                    KeyPair issuedCertKeyPair) throws Exception {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        X500Name issuedCertSubject = new X500Name("CN=" + ALIAS);
        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

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
                issuedCertExtUtils.createAuthorityKeyIdentifier(rootCertificate));
        issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

        issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature
                | KeyUsage.keyEncipherment));

        issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[]{
                new GeneralName(GeneralName.dNSName, requestInfo.getHost())
        }));

        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
        X509Certificate issuedCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);

        issuedCert.verify(rootCertificate.getPublicKey(), BC_PROVIDER);
        return issuedCert;
    }

    public KeyPair generateIssuedKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public SSLContext getSSLContext(HttpRequestInfo requestInfo, KeyPair issuedCertKeyPair,
                                     X509Certificate issuedCert, X509Certificate rootCertificate) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);

        keyStore.setKeyEntry(
                requestInfo.getHost(),
                issuedCertKeyPair.getPrivate(),
                PASSWORD.toCharArray(),
                new Certificate[]{issuedCert, rootCertificate}
        );

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(CERTIFICATE_TYPE);
        kmf.init(keyStore, PASSWORD.toCharArray());

        SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
        sslContext.init(
                kmf.getKeyManagers(),
                null,
                new SecureRandom()
        );
        return sslContext;
    }
}
