package ch.admin.bj.swiyu.clientattestation.config;

import ch.admin.bj.swiyu.clientattestation.ClientAttestationValidator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@EnableConfigurationProperties(AttestationProperties.class)
public class ClientAttestationAutoConfiguration {

    @Bean
    public ClientAttestationValidator clientAttestationValidator(AttestationProperties attestationProperties) {
        return new ClientAttestationValidator(attestationProperties);
    }
}

