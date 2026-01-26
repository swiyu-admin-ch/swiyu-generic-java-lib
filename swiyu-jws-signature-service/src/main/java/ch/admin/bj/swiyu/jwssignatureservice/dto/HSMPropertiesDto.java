package ch.admin.bj.swiyu.jwssignatureservice.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;
import org.springframework.util.StringUtils;

/**
 * Data Transfer Object for HSM (Hardware Security Module) properties.
 * Contains configuration details for connecting to and using an HSM.
 */
@Builder
@Getter
@Setter
@AllArgsConstructor
public class HSMPropertiesDto {
    private String userPin;
    private String keyId;
    private String keyPin;
    private String pkcs11Config;

    private String user;
    private String host;
    private String port;
    private String password;

    private String proxyUser;
    private String proxyPassword;

    /**
     * Default constructor for HSMPropertiesDto.
     * Required for frameworks and serialization.
     */
    public HSMPropertiesDto() {
        // Default constructor
    }

    /**
     * Builds a configuration string for Securosys Primus HSM provider.
     *
     * @return the configuration string for Securosys
     */
    @JsonIgnore
    public String getSecurosysStringConfig() {
        return getSecurosysConfigIfExists("credentials.host", getHost()) +
               getSecurosysConfigIfExists("credentials.port", getPort()) +
               getSecurosysConfigIfExists("primusProxyUser", getProxyUser()) +
               getSecurosysConfigIfExists("primusProxyPassword", getProxyPassword()) +
               getSecurosysConfigIfExists("credentials.user", getUser()) +
               getSecurosysConfigIfExists("credentials.password", getPassword());
    }

    /**
     * Returns a formatted property string if the value exists, otherwise an empty string.
     *
     * @param propertyName the property name
     * @param value the property value
     * @return formatted property string or empty string
     */
    private String getSecurosysConfigIfExists(String propertyName, String value) {
        if (!StringUtils.hasLength(value)) {
            return "";
        }
        return String.format("com.securosys.primus.jce.%s=%s%n", propertyName, value);
    }
}
