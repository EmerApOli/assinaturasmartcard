package emissaocetificado.contoller;

import emissaocetificado.entity.SignPdfForm;
import emissaocetificado.services.AssinaturaService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
 import org.jboss.resteasy.annotations.providers.multipart.MultipartForm;


@Path("/pdf")
public class AssinarPdfResource {

    @Inject
    AssinaturaService signatureService;

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
                    .entity(("Erro ao assinar PDF: " + e.getMessage()).getBytes())
                    .build();
        }
    }
}
