package emissaocetificado.services;

import com.itextpdf.kernel.pdf.StampingProperties;
import jakarta.enterprise.context.ApplicationScoped;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.*;

@ApplicationScoped
public class AssinaturaService {

    private static final String PKCS11_CFG = "C:/cert/pkcs11.cfg";
    private static Provider PKCS11_PROVIDER;

    static {

        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }


        try {
            Provider base = Security.getProvider("SunPKCS11");
            if (base == null) {
                throw new RuntimeException("SunPKCS11 não encontrado no JDK. Verifique a versão do Java.");
            }

            PKCS11_PROVIDER = base.configure(PKCS11_CFG);
            Security.addProvider(PKCS11_PROVIDER);

            System.out.println("PKCS11 Provider carregado: " + PKCS11_PROVIDER.getName());
        } catch (Exception e) {
            PKCS11_PROVIDER = null;
            System.err.println("Erro ao configurar PKCS11: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public byte[] signPdf(byte[] pdfBytes, byte[] p12Bytes, String password) throws Exception {

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(p12Bytes), password.toCharArray());

        Enumeration<String> aliases = ks.aliases();
        if (!aliases.hasMoreElements()) {
            throw new RuntimeException("Nenhum alias encontrado no keystore");
        }
        String alias = aliases.nextElement();

        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
        Certificate[] certChain = ks.getCertificateChain(alias);
        X509Certificate certificate = (X509Certificate) certChain[0];

        String nomeAssinante = extrairCN(certificate);
        System.out.println("Assinando (A1) com: " + nomeAssinante);

        ByteArrayOutputStream signedOut = new ByteArrayOutputStream();

        try (PdfReader reader = new PdfReader(new ByteArrayInputStream(pdfBytes))) {
            PdfSigner signer = new PdfSigner(reader, signedOut, new StampingProperties().useAppendMode());
            PdfSignatureAppearance appearance = signer.getSignatureAppearance();

            Rectangle rect = new Rectangle(20, 20, 160, 50);

            appearance
                    .setReason("Assinado digitalmente")
                    .setLocation("Brasil")
                    .setPageRect(rect)
                    .setPageNumber(1);

            URL seloUrl = Thread.currentThread()
                    .getContextClassLoader()
                    .getResource("imagens/selo-assinatura.png");

            if (seloUrl != null) {
                ImageData selo = ImageDataFactory.create(seloUrl);
                appearance.setSignatureGraphic(selo);
                appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
            } else {
                appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
            }

            signer.setFieldName("AssinaturaDigital");

            IExternalSignature pks = new PrivateKeySignature(privateKey, DigestAlgorithms.SHA256, "BC");
            IExternalDigest digest = new BouncyCastleDigest();

            signer.signDetached(
                    digest,
                    pks,
                    certChain,
                    null,
                    null,
                    null,
                    0,
                    PdfSigner.CryptoStandard.CMS
            );
        }

        return signedOut.toByteArray();
    }

    // 🔹 Assinatura A3 via SafeSign + PKCS11
    public byte[] signPdfPkcs11A3(byte[] pdfBytes, String pin) throws Exception {

        if (PKCS11_PROVIDER == null) {
            throw new IllegalStateException("Provider PKCS11 não carregado. Verifique o arquivo " + PKCS11_CFG);
        }

        if (pin == null || pin.isBlank()) {
            throw new IllegalArgumentException("PIN do certificado não informado.");
        }

        KeyStore ks = KeyStore.getInstance("PKCS11", PKCS11_PROVIDER);
        ks.load(null, pin.toCharArray());

        Enumeration<String> aliases = ks.aliases();
        if (!aliases.hasMoreElements()) {
            throw new RuntimeException("Nenhum alias encontrado no token A3");
        }
        String alias = aliases.nextElement();

        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, pin.toCharArray());
        Certificate[] certChain = ks.getCertificateChain(alias);
        X509Certificate certificate = (X509Certificate) certChain[0];

        String nomeAssinante = extrairCN(certificate);
        System.out.println("Assinando (A3) com: " + nomeAssinante);

        ByteArrayOutputStream signedOut = new ByteArrayOutputStream();

        try (PdfReader reader = new PdfReader(new ByteArrayInputStream(pdfBytes))) {

            PdfSigner signer = new PdfSigner(reader, signedOut, new StampingProperties().useAppendMode());
            PdfSignatureAppearance appearance = signer.getSignatureAppearance();

            Rectangle rect = new Rectangle(20, 20, 160, 50);

            appearance
                    .setReason("Assinado digitalmente")
                    .setLocation("Brasil")
                    .setPageRect(rect)
                    .setPageNumber(1);

            URL seloUrl = Thread.currentThread()
                    .getContextClassLoader()
                    .getResource("imagens/selo-assinatura.png");

            if (seloUrl != null) {
                ImageData selo = ImageDataFactory.create(seloUrl);
                appearance.setSignatureGraphic(selo);
                appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
            } else {
                appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
            }

            signer.setFieldName("AssinaturaDigital");

            IExternalSignature pks = new PrivateKeySignature(
                    privateKey,
                    DigestAlgorithms.SHA256,
                    PKCS11_PROVIDER.getName()
            );
            IExternalDigest digest = new BouncyCastleDigest();

            signer.signDetached(
                    digest,
                    pks,
                    certChain,
                    null,
                    null,
                    null,
                    0,
                    PdfSigner.CryptoStandard.CMS
            );
        }

        return signedOut.toByteArray();
    }

    private String extrairCN(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName();
        for (String part : dn.split(",")) {
            String p = part.trim();
            if (p.startsWith("CN=")) {
                return p.substring(3);
            }
        }
        return dn;
    }
}
