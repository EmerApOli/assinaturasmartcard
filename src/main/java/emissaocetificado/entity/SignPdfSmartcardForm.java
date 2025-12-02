package emissaocetificado.entity;

import jakarta.ws.rs.FormParam;
import org.jboss.resteasy.annotations.providers.multipart.PartType;
import jakarta.ws.rs.core.MediaType;

public class SignPdfSmartcardForm {

    @FormParam("pdfFile")
    @PartType(MediaType.APPLICATION_OCTET_STREAM)
    public byte[] pdfFile;

    @FormParam("pin")
    @PartType(MediaType.TEXT_PLAIN)
    public String pin;
}
