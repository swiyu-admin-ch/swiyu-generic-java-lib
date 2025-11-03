package ch.admin.bj.swiyu.clientattestation.config;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

@ConfigurationProperties(prefix = "swiyu.attestation")
@Data
@Slf4j
public class AttestationProperties {

    String attestationServiceDid;
    String didKeySuffix;

    Resource publicKeyPath;

    // New flag to enable/disable attestation verification. Defaults to false.
    boolean enabled = false;
}
