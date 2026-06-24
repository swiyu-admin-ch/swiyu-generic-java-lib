package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@Getter
@AllArgsConstructor
public enum ExampleTrustStatement {
    /**
     * identity-trust-statement
     */
    idTS("""
             {
                "typ": "swiyu-identity-trust-statement+jwt",
                "alg": "ES256",
                "kid": "did:example:trust-issuer#key-1",
            	"profile_version": "swiss-profile-trust:1.0.0"
            }""", """
            {
                "sub": "did:example:actor",
                "iat": 1690360968,
                "exp": 32503676400,
                "status":  {
                    "status_list": {
                      "idx": 1,
                      "uri": "https://example.com/statuslists/1"
                    }
                },
                "entity_name": "John Smith's Smithery",
                "entity_name#de": "John Smith's Schmiderei",
                "entity_name#de-CH": "John Smith's Schmiderei",
                "is_state_actor": false,
                "registry_ids": [
                  {
                    "type": "UID",
                    "value": "CHE-000.000.000"
                  },
                  {
                    "type": "LEI",
                    "value": "0A1B2C3D4E5F6G7H8J9I"
                  }
                ]
            }"""),
    /**
     * verification-query-public-statement with a protected claim
     */
    vqPS_protected_claim("""
            {
                "typ": "swiyu-verification-query-public-statement+jwt",
                "alg": "ES256",
                "kid": "did:example:verification-statment-issuer#key-1",
            	"profile_version": "swiss-profile-trust:1.0.0"
            }
            """, """
            {
               "jti": "07f289d5-8b1f-4604-bf72-53bdcb71ee05",
               "sub":"did:example:actor",
               "iat":1690360968,
               "exp":32503676400,
               "purpose_name":"beispiel abfrage",
               "purpose_name#de-ch":"beispiel abfrage",
               "purpose_description":"frage ab zum beispiel",
               "purpose_description#de-ch":"frage ab zum beispiel",
               "request": {
                  "type":"DCQL",
                  "scope": "com.example.identityCardCredential_presentation",
                  "query":{
                     "credentials":[
                        {
                           "id":"my_credential",
                           "format":"dc+sd-jwt",
                           "meta":{
                              "vct_values":[
                                 "https://credentials.example.com/identity_credential"
                              ]
                           },
                           "claims":[
                              {
                                 "path":[
                                    "personal_administrative_number"
                                 ]
                              }
                           ]
                        }
                     ]
                  }
               }
            }
            """),
    /**
     * verification-query-public-statement
     */
    vqPS("""
            {
                "typ": "swiyu-verification-query-public-statement+jwt",
                "alg": "ES256",
                "kid": "did:example:verification-statment-issuer#key-1",
            	"profile_version": "swiss-profile-trust:1.0.0"
            }
            """, """
            {
               "jti": "07f289d5-8b1f-4604-bf72-53bdcb71ee05",
               "sub":"did:example:actor",
               "iat":1690360968,
               "exp":32503676400,
               "purpose_name":"beispiel abfrage",
               "purpose_name#de-ch":"beispiel abfrage",
               "purpose_description":"frage ab zum beispiel",
               "purpose_description#de-ch":"frage ab zum beispiel",
               "request": {
                  "type":"DCQL",
                  "scope": "com.example.identityCardCredential_presentation",
                  "query":{
                     "credentials":[
                        {
                           "id":"my_credential",
                           "format":"dc+sd-jwt",
                           "meta":{
                              "vct_values":[
                                 "https://credentials.example.com/identity_credential"
                              ]
                           },
                           "claims":[
                              {
                                 "path":[
                                    "name"
                                 ]
                              }
                           ]
                        }
                     ]
                  }
               }
            }
            """),
    /**
     * protected-verification-authorization-trust-statement
     */
    pvaTS("""
            {
                "typ": "swiyu-protected-verification-authorization-trust-statement+jwt",
                "alg": "ES256",
                "kid": "did:example:trust-issuer#key-1",
            	"profile_version": "swiss-profile-trust:1.0.0"
            }
            """, """
            {
              "jti": "07f289d5-8b1f-4604-bf72-53bdcb71ee05",
              "sub": "did:example:actor",
              "iat": 1690360968,
              "exp": 32503676400,
              "status": {
                "status_list": {
                  "idx": 1,
                  "uri": "https://example.com/statuslists/1"
                }
              },
              "authorized_fields": [
                "personal_administrative_number"
              ]
            }"""),
    /**
     * protected-issuance-authorization-trust-statement
     */
    piaTS("""
            {
                "typ": "swiyu-protected-issuance-authorization-trust-statement+jwt",
                "alg": "ES256",
                "kid": "did:example:trust-issuer#key-1",
            	"profile_version": "swiss-profile-trust:1.0.0"
            }
            """, """
            {
              "jti": "07f289d5-8b1f-4604-bf72-53bdcb71ee05",
              "sub": "did:example:actor",
              "iat": 1690360968,
              "exp": 32503676400,
              "status": {
                "status_list": {
                  "idx": 1,
                  "uri": "https://example.com/statuslists/1"
                }
              },
              "can_issue": {
                "vct": "urn:ch.admin.fedpol.betaid",
                "vct_name": "Beta credential",
                "reason": "This issuer is eglible to issue Beta credentials due to AwG Art.6b"
              }
            }
            """),
    /**
     * protected-issuance-trust-list-statement
     */
    piTLS("""
            {
                "typ": "swiyu-protected-issuance-trust-list-statement+jwt",
                "alg": "ES256",
                "kid": "did:example:trust-issuer#key-1",
            	"profile_version": "swiss-profile-trust:1.0.0"
            }
            """, """
            {
              "jti": "07f289d5-8b1f-4604-bf72-53bdcb71ee05",
              "iat": 1690360968,
              "exp": 32503676400,
              "status": {
                "status_list": {
                  "idx": 1,
                  "uri": "https://example.com/statuslists/1"
                }
              },
              "vct_values": [
                "urn:ch.admin.fedpol.eid",
                "urn:ch.admin.fedpol.betaid"
              ]
            }"""),
    /**
     * non-compliance-trust-list-statement
     */
    ncTLS("""
                {
                "typ": "swiyu-non-compliance-trust-list-statement+jwt",
                "alg": "ES256",
                "kid": "did:example:trust-issuer#key-1",
            	"profile_version": "swiss-profile-trust:1.0.0"
            }""",
            """
                    {
                      "iat": 1690360968,
                      "exp": 32503676400,
                      "status": {
                        "status_list": {
                          "idx": 1,
                          "uri": "https://example.com/statuslists/1"
                        }
                      },
                      "non_compliant_actors": [
                        {
                          "actor": "did:example:badActor",
                          "flagged_at": "2026-02-25T07:07:35Z",
                          "reason": "The issuer is not who they claim to be (DE)",
                          "reason#de": "The issuer is not who they claim to be (DE)",
                          "reason#en": "The issuer is not who they claim to be (EN)",
                          "reason#fr-CH": "The issuer is not who they claim to be (FR)",
                          "reason#it-CH": "The issuer is not who they claim to be (IT)",
                          "reason#rm-CH": "The issuer is not who they claim to be (RM)"
                        },
                        {
                          "actor": "did:example:badActor2",
                          "flagged_at": "2025-01-13T07:13:00Z",
                          "reason": "The verifier is not who they claim to be (DE)",
                          "reason#de": "The verifier is not who they claim to be (DE)",
                          "reason#en": "The verifier is not who they claim to be (EN)",
                          "reason#fr-CH": "The verifier is not who they claim to be (FR)",
                          "reason#it-CH": "The verifier is not who they claim to be (IT)",
                          "reason#rm-CH": "The verifier is not who they claim to be (RM)"
                        }
                      ]
                    }
                    """);

    private final String header;
    private final String body;

    public String getBodyJson() {
        var mapper = new ObjectMapper();
        HashMap<String, Object> claims = new HashMap<>();
        assertDoesNotThrow(() -> claims.putAll(mapper.readValue(this.getBody(), Map.class)));
        return assertDoesNotThrow(() -> mapper.writeValueAsString(claims));
    }

    public String getHeaderJson() {
        var mapper = new ObjectMapper();
        HashMap<String, Object> claims = new HashMap<>();
        assertDoesNotThrow(() -> claims.putAll(mapper.readValue(this.getHeader(), Map.class)));
        return assertDoesNotThrow(() -> mapper.writeValueAsString(claims));
    }

    public String getSerializedJwt(ECKey privateKey) {
        var jwt = assertDoesNotThrow(() -> new SignedJWT(JWSHeader.parse(header), JWTClaimsSet.parse(body)));
        assertDoesNotThrow(() -> jwt.sign(new ECDSASigner(privateKey)));
        return jwt.serialize();
    }
}
