package emissaocetificado.services;

import jakarta.enterprise.context.ApplicationScoped;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

@ApplicationScoped
public class CertificadoA1Service {

    static {
        // garante provider registrado
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public byte[] gerarPkcs12(String subjectDn,
                              int diasValidade,
                              String senhaPkcs12) throws Exception {

        // 1) Gera par de chaves
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // 2) Dados de validade
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + (long) diasValidade * 24 * 60 * 60 * 1000);

        // 3) Subject = Issuer (self-signed)
        X500Name subject = new X500Name(subjectDn);
        BigInteger serial = new BigInteger(64, new SecureRandom());

        JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        subject,
                        serial,
                        notBefore,
                        notAfter,
                        subject,
                        keyPair.getPublic()
                );

        // 4) Assina o certificado
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);

        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);

        // 5) Cria o PKCS12 na memória
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        Certificate[] chain = new Certificate[]{certificate};

        ks.setKeyEntry(
                "a1-key",                       // alias
                keyPair.getPrivate(),          // chave privada
                senhaPkcs12.toCharArray(),     // senha
                chain                          // cadeia de certificados
        );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ks.store(baos, senhaPkcs12.toCharArray());

        return baos.toByteArray(); // bytes do .p12
    }
}
