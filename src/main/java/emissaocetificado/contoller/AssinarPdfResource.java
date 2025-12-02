package emissaocetificado.contoller;

import emissaocetificado.entity.SignPdfForm;
import emissaocetificado.entity.SignPdfSmartcardForm;
import emissaocetificado.services.AssinaturaService;

import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.resteasy.annotations.providers.multipart.MultipartForm;

@Path("/pdf")
public class AssinarPdfResource {

    @Inject
    AssinaturaService signatureService;

    // 🔹 A1 (.p12)
    @POST
    @Path("/sign")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces("application/pdf")
    public Response signPdf(@MultipartForm SignPdfForm form) {
        try {
            byte[] signed = signatureService.signPdf(
                    form.pdfFile,
                    form.p12File,
                    form.password
            );

            return Response.ok(signed)
                    .header("Content-Disposition", "attachment; filename=\"assinado.pdf\"")
                    .build();

        } catch (Exception e) {
            e.printStackTrace();
            return Response.status(500)
                    .entity(("Erro ao assinar PDF (A1): " + e.getMessage()).getBytes())
                    .build();
        }
    }

    // 🔹 A3 (token/cartão via PKCS11)
    @POST
    @Path("/sign-a3")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces("application/pdf")
    public Response signPdfA3(@MultipartForm SignPdfSmartcardForm form) {
        try {
            byte[] signed = signatureService.signPdfPkcs11A3(
                    form.pdfFile,
                    form.pin
            );

            return Response.ok(signed)
                    .header("Content-Disposition", "attachment; filename=\"assinado-a3.pdf\"")
                    .build();

        } catch (Exception e) {
            e.printStackTrace();
            return Response.status(500)
                    .entity(("Erro ao assinar PDF (A3): " + e.getMessage()).getBytes())
                    .build();
        }
    }
}
