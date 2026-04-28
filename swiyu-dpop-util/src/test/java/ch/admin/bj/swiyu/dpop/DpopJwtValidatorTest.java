package ch.admin.bj.swiyu.dpop;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DpopJwtValidatorTest {

    @Test
    void parse_validJwt_returnsSignedJwt() throws Exception {
        SignedJWT signedJWT = buildSignedJwt();
        SignedJWT parsed = DpopJwtValidator.parse(signedJWT.serialize());
        assertDoesNotThrow(() -> DpopJwtValidator.validateSignature(parsed, signedJWT.getHeader().getJWK()));
    }

    @Test
    void validateMandatoryClaims_missingHeaderClaim_throws() {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(DpopConstants.DPOP_JWT_HEADER_TYP)).build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().build();
        assertThrows(DpopValidationException.class, () -> DpopJwtValidator.validateMandatoryClaims(header, claims));
    }

    @Test
    void validateMandatoryClaims_missingPayloadClaim_throws() throws Exception {
        ECKey key = buildEcKey();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(DpopConstants.DPOP_JWT_HEADER_TYP)).jwk(key.toPublicJWK()).build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().jwtID("jti").claim("htm", "GET").claim("htu", "https://example.com").issueTime(new Date()).build();
        assertThrows(DpopValidationException.class, () -> DpopJwtValidator.validateMandatoryClaims(header, claims));
    }

    @Test
    void validateTyp_invalid_throws() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("JWT")).jwk(buildEcKey().toPublicJWK()).build();
        assertThrows(DpopValidationException.class, () -> DpopJwtValidator.validateTyp(header));
    }

    @Test
    void validateAlgorithm_unsupported_throws() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(DpopConstants.DPOP_JWT_HEADER_TYP)).jwk(buildEcKey().toPublicJWK()).build();
        assertThrows(DpopValidationException.class, () -> {
            DpopJwtValidator.validateAlgorithm(header, List.of("RS256"));
        });
    }

    @Test
    void validateSignature_invalid_throws() throws Exception {
        ECKey key1 = buildEcKey();
        ECKey key2 = buildEcKey();
        SignedJWT signedJWT = buildSignedJwt(key1);
        JWK wrongKey = key2.toPublicJWK();
        assertThrows(DpopValidationException.class, () -> DpopJwtValidator.validateSignature(signedJWT, wrongKey));
    }

    @Test
    void validateSignature_valid_ok() throws Exception {
        ECKey key = buildEcKey();
        SignedJWT signedJWT = buildSignedJwt(key);
        assertDoesNotThrow(() -> DpopJwtValidator.validateSignature(signedJWT, key.toPublicJWK()));
    }

    @Test
    void validatePublicKeyNotPrivate_privateKey_throws() throws Exception {
        ECKey key = buildEcKey();
        assertThrows(DpopValidationException.class, () -> DpopJwtValidator.validatePublicKeyNotPrivate(key));
    }

    @Test
    void validatePublicKeyNotPrivate_publicKey_ok() throws Exception {
        ECKey key = buildEcKey();
        assertDoesNotThrow(() -> DpopJwtValidator.validatePublicKeyNotPrivate(key.toPublicJWK()));
    }

    @Test
    void validateHtm_mismatch_throws() throws Exception {
        SignedJWT signedJWT = buildSignedJwt();
        assertThrows(DpopValidationException.class, () -> DpopJwtValidator.validateHtm("POST", signedJWT.getJWTClaimsSet()));
    }

    @Test
    void validateHtm_match_ok() throws Exception {
        SignedJWT signedJWT = buildSignedJwt();
        assertDoesNotThrow(() -> DpopJwtValidator.validateHtm("GET", signedJWT.getJWTClaimsSet()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://internal.local", "https://api.example.com"})
    void validateHtu_match_ok(String requestUriHost) throws Exception {
        SignedJWT signedJWT = buildSignedJwt("https://api.example.com/resource");
        URI requestUri = new URI("%s/resource".formatted(requestUriHost));
        URI externalUri = new URI("https://api.example.com");
        assertDoesNotThrow(() -> DpopJwtValidator.validateHtu(requestUri, signedJWT.getJWTClaimsSet().getStringClaim("htu"), externalUri));
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://internal.local", "https://api.example.com", "https://api.example.com/public/api"})
    void validateHtu_match_rewrite_path_ok(String requestUriHost) throws Exception {
        SignedJWT signedJWT = buildSignedJwt("https://api.example.com/public/api/resource");
        URI requestUri = new URI("%s/resource".formatted(requestUriHost));
        URI externalUri = new URI("https://api.example.com/public/api");
        assertDoesNotThrow(() -> DpopJwtValidator.validateHtu(requestUri, signedJWT.getJWTClaimsSet().getStringClaim("htu"), externalUri));
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://internal.local", "https://api.example.com"})
    void validateHtu_mismatch_host_throws(String requestUriHost) throws Exception {
        SignedJWT signedJWT = buildSignedJwt("https://example.com/resource");
        URI requestUri = new URI("%s/resource".formatted(requestUriHost));
        URI externalUri = new URI("https://api.example.com");
        assertThrows(DpopValidationException.class, () -> DpopJwtValidator.validateHtu(requestUri, signedJWT.getJWTClaimsSet().getStringClaim("htu"), externalUri));
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://internal.local", "https://api.example.com"})
    void validateHtu_mismatch_resource_throws(String requestUriHost) throws Exception {
        SignedJWT signedJWT = buildSignedJwt("https://api.example.com/resource");
        URI requestUri = new URI("%s/credential".formatted(requestUriHost));
        URI externalUri = new URI("https://api.example.com");
        assertThrows(DpopValidationException.class, () -> DpopJwtValidator.validateHtu(requestUri, signedJWT.getJWTClaimsSet().getStringClaim("htu"), externalUri));
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://internal.local", "https://api.example.com"})
    void validateHtu_rewrite_path_injected_throws(String requestUriHost) throws Exception {
        SignedJWT signedJWT = buildSignedJwt("https://api.example.com/public/api/resource");
        URI requestUri = new URI("%s/injected/resource".formatted(requestUriHost));
        URI externalUri = new URI("https://api.example.com/public/api");
        assertThrows(DpopValidationException.class, () -> DpopJwtValidator.validateHtu(requestUri, signedJWT.getJWTClaimsSet().getStringClaim("htu"), externalUri));
    }

    @Test
    void validateHtu_rewrite_path_missing_subresource_throws() throws Exception {
        SignedJWT signedJWT = buildSignedJwt("https://api.example.com/public/api/subresource/resource");
        URI requestUri = new URI("https://api.example.com/resource");
        URI externalUri = new URI("https://api.example.com/public/api");
        assertThrows(DpopValidationException.class, () -> DpopJwtValidator.validateHtu(requestUri, signedJWT.getJWTClaimsSet().getStringClaim("htu"), externalUri));
    }

    @Test
    void validateIssuedAt_outsideWindow_throws() throws Exception {
        Instant now = Instant.parse("2024-01-01T00:00:00Z");
        Clock fixedClock = Clock.fixed(now, ZoneOffset.UTC);
        JWTClaimsSet claims = new JWTClaimsSet.Builder().issueTime(Date.from(now.minusSeconds(120))).build();
        assertThrows(DpopValidationException.class, () -> DpopJwtValidator.validateIssuedAt(claims, 30, fixedClock));
    }

    @Test
    void validateIssuedAt_withinWindow_ok() throws Exception {
        Instant now = Instant.parse("2024-01-01T00:00:00Z");
        Clock fixedClock = Clock.fixed(now, ZoneOffset.UTC);
        JWTClaimsSet claims = new JWTClaimsSet.Builder().issueTime(Date.from(now.minusSeconds(10))).build();
        assertDoesNotThrow(() -> DpopJwtValidator.validateIssuedAt(claims, 30, fixedClock));
    }

    private static SignedJWT buildSignedJwt() throws Exception {
        return buildSignedJwt(buildEcKey());
    }

    private static SignedJWT buildSignedJwt(String htu) throws Exception {
        ECKey key = buildEcKey();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().jwtID("jti").claim("htm", "GET").claim("htu", htu).issueTime(new Date()).claim("nonce", "n").build();
        return signJwt(key, claims);
    }

    private static SignedJWT buildSignedJwt(ECKey key) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().jwtID("jti").claim("htm", "GET").claim("htu", "https://example.com/resource").issueTime(new Date()).claim("nonce", "n").build();
        return signJwt(key, claims);
    }

    private static SignedJWT signJwt(ECKey key, JWTClaimsSet claims) throws JOSEException {
        JWSSigner signer = new ECDSASigner(key);
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(DpopConstants.DPOP_JWT_HEADER_TYP)).jwk(key.toPublicJWK()).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(signer);
        return jwt;
    }

    private static ECKey buildEcKey() throws JOSEException {
        return new ECKeyGenerator(Curve.P_256).keyID("kid").generate();
    }
}

