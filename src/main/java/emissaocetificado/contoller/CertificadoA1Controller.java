package emissaocetificado.contoller;
import emissaocetificado.entity.DadosGerarA1;
import emissaocetificado.services.CertificadoA1Service;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
@ApplicationScoped
@Path("/certificados")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_OCTET_STREAM)
public class CertificadoA1Controller {


    @Inject
    CertificadoA1Service certificadoA1Service;

    @POST
    @Path("/a1")
    public Response gerarA1(DadosGerarA1 dadosGerarA1) {
        try {
            String subjectDn = String.format(
                    "C=%s, ST=%s, O=%s, OU=%s, CN=%s",
                    nvl(dadosGerarA1.pais, "BR"),
                    nvl(dadosGerarA1.uf, "SP"),
                    nvl(dadosGerarA1.organizacao, "Minha Empresa"),
                    nvl(dadosGerarA1.organizacaoUnidade, "TI"),
                    nvl(dadosGerarA1.cn, "Usuario")
            );

            int dias = dadosGerarA1.diasValidade > 0 ? dadosGerarA1.diasValidade : 365;

            byte[] pkcs12Bytes = certificadoA1Service.gerarPkcs12(
                    subjectDn,
                    dias,
                    dadosGerarA1.senhaPkcs12
            );

            String fileName = "certificado-a1.p12";

            return Response.ok(pkcs12Bytes)
                    .header("Content-Disposition",
                            "attachment; filename=\"" + fileName + "\"")
                    .build();

        } catch (Exception e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(("Erro ao gerar certificado: " + e.getMessage()).getBytes())
                    .build();
        }
    }

    private String nvl(String v, String def) {
        return (v == null || v.isBlank()) ? def : v;
    }






}
