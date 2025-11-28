package emissaocetificado.entity;


import jakarta.persistence.Entity;
import lombok.*;

@Data
@Builder
@NoArgsConstructor // Gera o construtor padrão
@AllArgsConstructor
@Entity
@EqualsAndHashCode(callSuper=false)
public class DadosGerarA1 {


    public String cn;                // Common Name
    public String organizacao;       // O
    public String organizacaoUnidade;// OU
    public String uf;                // ST
    public String pais;              // C
    public int diasValidade;         // ex: 365
    public String senhaPkcs12;


}
