package ch.admin.bj.swiyu.clientattestation;


import ch.admin.bj.swiyu.clientattestation.config.AttestationProperties;
import com.nimbusds.jose.Header;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import org.erdtman.jcs.JsonCanonicalizer;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class ClientAttestationValidator {

    private final AttestationProperties attestationProperties;

    private ECPublicKey publicKey;

    @PostConstruct
    void init() {
        if(attestationProperties.isEnabled()) {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            try {
                this.publicKey = loadEcPublicKey(attestationProperties.getPublicKeyPath());
                log.info("Loaded EC attestation public key");
            } catch (Exception e) {
                log.error("Failed to load EC attestation public key", e);
                this.publicKey = null;
            }
        }
    }

    public boolean isAttested(String attestation, String pop, String body) {
        if (!attestationProperties.isEnabled()) {
            log.info("Attestation verification is disabled; accepting request");
            return true;
        }
        if (publicKey == null) {
            log.warn("No EC attestation public key loaded; rejecting request");
            return false;
        }
        try {
            return validate(attestation, pop, body);
        } catch (Exception e) {
            log.error("Attestation EC verification failed", e);
            return false;
        }
    }

    public boolean validate(String attestation, String pop, String body) {
        try {
            SignedJWT signedJWTPoP = SignedJWT.parse(pop);
            log.info("PoP Payload: {}", signedJWTPoP.getPayload().toJSONObject());
            log.info("PoP Header: {}", signedJWTPoP.getHeader().toJSONObject());
            JWTClaimsSet claimsSetPoP = signedJWTPoP.getJWTClaimsSet();
            JWSHeader headerPoP = signedJWTPoP.getHeader();

            SignedJWT signedJWT = SignedJWT.parse(attestation);
            log.info("Attestation Payload: {}", signedJWT.getPayload().toJSONObject());
            log.info("Attestation Header: {}", signedJWT.getHeader().toJSONObject());
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            Header headerAttest = signedJWT.getHeader();

            Instant now = Instant.now();

            // check hash
            String reqClaim = claimsSetPoP.getStringClaim("req");
            if (!verifyHash(reqClaim, body)) {
                log.info("PoP req hash validation failed");
                return false;
            }


            // check expiration
            Instant expAttestation = claimsSet.getExpirationTime().toInstant();
            if (expAttestation.isBefore(now)) {
                log.info("Attestation expired at {}", expAttestation);
                return false;
            }

            // check nbf
            Instant nbf = claimsSet.getNotBeforeTime().toInstant();
            if (nbf.isAfter(now)) {
                log.info("Attestation nbf {} is after now {}", nbf, now);
                return false;
            }

            // check issuer DID from payload
            String iss = claimsSet.getStringClaim("iss");
            if (iss == null || !iss.equals(attestationProperties.getAttestationServiceDid())) {
                log.info("Wrong issuer {}", iss);
                return false;
            }

            // check issuer KID from header
            String kid = headerAttest.toJSONObject().get("kid").toString();
            if (!kid.equals(attestationProperties.getAttestationServiceDid() + attestationProperties.getDidKeySuffix())) {
                log.info("Wrong kid {}", kid);
                return false;
            }

            // check type from header
            String typ = headerAttest.toJSONObject().get("typ").toString();
            if (!"oauth-client-attestation+jwt".equals(typ)) {
                log.info("Wrong typ {}", typ);
                return false;
            }

            // extract key from attestation cnf.jwk
            Object cnf = claimsSet.getClaim("cnf");
            if (cnf == null) {
                log.info("Missing 'cnf' claim in JWT payload");
                return false;
            }

            ECKey attestatedEcKey = parseJwk(((Map<String, Object>) cnf).get("jwk"));

            // check expiration POP
            Instant expPoP = claimsSetPoP.getExpirationTime().toInstant();
            if (expPoP.isBefore(now)) {
                log.info("PoP expired at {}", expPoP);
                return false;
            }

            // check type from header
            typ = headerPoP.toJSONObject().get("typ").toString();
            if (!"oauth-client-attestation-pop+jwt".equals(typ)) {
                log.info("Wrong PoP typ {}", typ);
                return false;
            }

            Object jwkString = headerPoP.toJSONObject().get("jwk");
            ECKey ecKeyPoP = parseJwk(jwkString);

            // check signature PoP
            JWSVerifier verifier = new ECDSAVerifier(ecKeyPoP);
            if (!signedJWTPoP.verify(verifier)) {
                log.info("PoP not signed by public key");
                return false;
            }

            // validate pop key = attestation key
            if (!compareKeys(attestatedEcKey, ecKeyPoP)) {
                log.info("PoP key and attested key do not match");
                return false;
            }

            // ✅ all checks passed
            return true;

        } catch (Exception e) {
            log.info("Failed to verify attestation", e);
            return false;
        }
    }

    /**
     * Verifies that the hash of the canonicalized JSON raw body matches the given claim.
     * Returns true if the hash matches, false otherwise.
     *
     * @param reqClaim the expected hash (Base64 or hex)
     * @param rawBody  the raw JSON body
     * @return boolean whether the hash matches
     */
    private boolean verifyHash(String reqClaim, String rawBody) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            JsonCanonicalizer jc = new JsonCanonicalizer(rawBody);
            byte[] canonicalJsonBytes = jc.getEncodedString().getBytes(StandardCharsets.UTF_8);
            byte[] hash = digest.digest(canonicalJsonBytes);

            String computedBase64 = Base64.getEncoder().encodeToString(hash);

            // Normalize Base64 comparison to avoid padding differences
            boolean matches = normalizeBase64(reqClaim).equals(normalizeBase64(computedBase64))
                    || reqClaim.equalsIgnoreCase(bytesToHex(hash));

            if (!matches) {
                log.info("raw body {}", rawBody);
                log.info("canonicalized json {}", jc.getEncodedString());
                log.info("hash mismatch: computed={} vs reqClaim={}", computedBase64, reqClaim);
            }
            return matches;

        } catch (Exception e) {
            log.warn("Failed to compute or verify hash", e);
            return false;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static String normalizeBase64(String base64) {
        // Remove trailing '=' padding
        int end = base64.length();
        while (end > 0 && base64.charAt(end - 1) == '=') {
            end--;
        }
        String noPadding = base64.substring(0, end);
        return noPadding.replace('+', '-').replace('/', '_');
    }


    private boolean compareKeys(ECKey key1, ECKey key2) {
        return
                key1.getX().equals(key2.getX()) &&
                        key1.getY().equals(key2.getY()) &&
                        key1.getCurve().equals(key2.getCurve());
    }

    private ECKey parseJwk(Object jwkString) throws ParseException {
        // Extract the 'jwk' object from the header
        if (jwkString == null) {
            throw new IllegalArgumentException("JWT header does not contain 'jwk'");
        }
        // Convert it into a JWK
        JWK jwk = JWK.parse(jwkString.toString());
        if (!(jwk instanceof ECKey)) {
            throw new IllegalArgumentException("JWK is not an EC key");
        }
        return (ECKey) jwk;
    }


    private static ECPublicKey loadEcPublicKey(Resource resource) throws IOException {
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
            Object parsed = pemParser.readObject();
            if (!(parsed instanceof SubjectPublicKeyInfo spki)) {
                throw new IllegalArgumentException("Unsupported PEM object; expected SubjectPublicKeyInfo");
            }
            PublicKey pk = new JcaPEMKeyConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getPublicKey(spki);
            if (!(pk instanceof ECPublicKey ec)) {
                throw new IllegalArgumentException("Provided key is not an EC public key");
            }
            return ec;
        }
    }
}
