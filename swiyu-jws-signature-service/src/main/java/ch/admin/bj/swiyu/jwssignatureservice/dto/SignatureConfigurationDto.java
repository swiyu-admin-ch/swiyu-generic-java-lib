package ch.admin.bj.swiyu.jwssignatureservice.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

/**
 * Data Transfer Object for signature configuration.
 * Contains information for key management and verification method.
 */
@Builder
@Valid
@Data
@AllArgsConstructor
public class SignatureConfigurationDto {
    /**
     * Method of signing key management.
     */
    @NotNull
    private String keyManagementMethod;
    /**
     * Private Key, if the key is not managed by HSM.
     * This includes vault or just mounted as environment variable.
     */
    private String privateKey;

    /**
     * Configuration Information for connecting to HSM and using an HSM Key.
     */
    private HSMPropertiesDto hsm;

    /**
     * Location of the config file, see the <a href="https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html">official java documentation</a>.
     */
    private String pkcs11Config;

    /**
     * The id of the verification method in the did document with which a verifier can check the issued VC.
     * In did tdw/webvh this is the full did#fragment.
     */
    @NotEmpty
    private String verificationMethod;

    /**
     * Default constructor for SignatureConfigurationDto.
     * Required for frameworks and serialization.
     */
    public SignatureConfigurationDto() {
    }
}
