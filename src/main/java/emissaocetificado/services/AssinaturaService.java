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

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public byte[] signPdf(byte[] pdfBytes, byte[] p12Bytes, String password) throws Exception {

        // 🔹 Carrega o PKCS12
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

        // 🔹 nomeAssinante ainda é usado só para auditoria/log se quiser
        String nomeAssinante = extrairCN(certificate);

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

    private String extrairCN(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName(); // exemplo: CN=Fulano, OU=Depto, O=Empresa
        for (String part : dn.split(",")) {
            String p = part.trim();
            if (p.startsWith("CN=")) {
                return p.substring(3); // remove "CN="
            }
        }
        return dn; // fallback
    }
}
