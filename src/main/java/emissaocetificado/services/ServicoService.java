package emissaocetificado.services;

import jakarta.enterprise.context.ApplicationScoped;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import com.itextpdf.kernel.pdf.*;
import com.itextpdf.signatures.*;
public class ServicoService {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public byte[] signPdf(byte[] pdfBytes, byte[] p12Bytes, String password) throws Exception {

        // 🔹 Carrega o PKCS12
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(p12Bytes), password.toCharArray());

        String alias = ks.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
        Certificate[] certChain = ks.getCertificateChain(alias);

        X509Certificate certificate = (X509Certificate) certChain[0];

        // 🔹 Instanciar PDF
        ByteArrayOutputStream signedOut = new ByteArrayOutputStream();

        PdfReader pdfReader = new PdfReader(new ByteArrayInputStream(pdfBytes));
        PdfWriter pdfWriter = new PdfWriter(signedOut);

        PdfDocument pdfDoc = new PdfDocument(pdfReader, pdfWriter);
        PdfSigner signer = new PdfSigner(pdfReader, signedOut, new StampingProperties());

        // 🔹 Criar aparência da assinatura (visível ou invisível)
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance
                .setReason("Assinado digitalmente")
                .setLocation("Brasil")
                .setContact("email@empresa.com");

        signer.setFieldName("AssinaturaDigital");

        // 🔹 Preparar assinatura
        IExternalSignature pks = new PrivateKeySignature(privateKey, DigestAlgorithms.SHA256, "BC");
        IExternalDigest digest = new BouncyCastleDigest();

        // 🔹 Assinar
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

        return signedOut.toByteArray();
    }


}
