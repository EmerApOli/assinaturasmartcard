package emissaocetificado.entity;

import org.jboss.resteasy.annotations.providers.multipart.PartType;

import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.core.MediaType;

public class SignPdfForm {

    @FormParam("pdf")
    @PartType(MediaType.APPLICATION_OCTET_STREAM)
    public byte[] pdfFile;

    @FormParam("p12")
    @PartType(MediaType.APPLICATION_OCTET_STREAM)
    public byte[] p12File;

    @FormParam("password")
    @PartType(MediaType.TEXT_PLAIN)
    public String password;
}
