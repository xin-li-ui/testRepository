package com.test.controller;



import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.auth0.jwt.interfaces.Verification;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.test.model.ChallengeResult;
import com.test.model.ReturnVO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * date  2022/6/20 3:15 PM
 * @version 1.0
 */
@Slf4j
@RestController
@RequestMapping
public class OIDCController {


    @PostMapping("/api/challenge")
    public ReturnVO test() throws JsonProcessingException {
        ChallengeResult data = ChallengeResult.builder()
                .status(ChallengeResult.TransactionStatus.SUCCESS)
                .stateToken("challenge")
                .stateTokenExpiredAt(Instant.now().plus(10, ChronoUnit.MINUTES).getEpochSecond())
                .build();
        return ReturnVO.success(data);
    }


    @PostMapping("/doLogin")
    public ReturnVO doLogin() {
        ChallengeResult data = ChallengeResult.builder()
                .status(ChallengeResult.TransactionStatus.SUCCESS)
                .stateToken("challenge")
                .stateTokenExpiredAt(Instant.now().plus(10, ChronoUnit.MINUTES).getEpochSecond())
                .build();
        return ReturnVO.success(data);
    }


    @GetMapping("/api/v1/admin")
    public String test2() throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, String> map = new HashMap<>();
        map.put("id", "123");
        map.put("name", "admin");
        return objectMapper.writeValueAsString(map);
    }

    public static void main(String[] args) {

        String token = "eyJraWQiOiI2OWFhYmNhMy03M2JhLTQzNjEtODJkNS05ZDc1MDc0NWRlOGMiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4aW4ubGlAdWkuY29tIiwiem9uZWluZm8iOiJFdXJvcGUvUGFyaXMiLCJiaXJ0aGRhdGUiOiIxOTcwLTAxLTAxIiwiZ2VuZGVyIjoiZmVtYWxlIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwicHJlZmVycmVkX3VzZXJuYW1lIjoieGluLmxpQHVpLmNvbSIsImxvY2FsZSI6ImVuLVVTIiwic2lkIjoib3hZT2JqandxTlF0NjlLWWF3YmE1aF9YTHhUMlRyNFRfUG0wOUxiV3B1TSIsInVwZGF0ZWRfYXQiOiIxOTcwLTAxLTAxVDAwOjAwOjAwWiIsImF6cCI6IkRJNEE5RElYR1ZEUkxDMkJFQkFQIiwiYXV0aF90aW1lIjoxNjk3NTM4NjkwLCJuaWNrbmFtZSI6IlVzZXIiLCJleHAiOjE2OTc1NDA1MjQsImlhdCI6MTY5NzUzODcyNCwiZW1haWwiOiJ4aW4ubGlAdWkuY29tQGV4YW1wbGUuY29tIiwid2Vic2l0ZSI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYWRkcmVzcyI6eyJmb3JtYXR0ZWQiOiJDaGFtcCBkZSBNYXJzXG41IEF2LiBBbmF0b2xlIEZyYW5jZVxuNzUwMDcgUGFyaXNcbkZyYW5jZSJ9LCJwcm9maWxlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS94aW4ubGlAdWkuY29tIiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIjpmYWxzZSwiZ2l2ZW5fbmFtZSI6IkZpcnN0IiwibWlkZGxlX25hbWUiOiJNaWRkbGUiLCJwaWN0dXJlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS94aW4ubGlAdWkuY29tLmpwZyIsImF1ZCI6IkRJNEE5RElYR1ZEUkxDMkJFQkFQIiwibmFtZSI6IkZpcnN0IExhc3QiLCJwaG9uZV9udW1iZXIiOiIrMSAoNjA0KSA1NTUtMTIzNDtleHQ9NTY3OCIsImZhbWlseV9uYW1lIjoiTGFzdCJ9.IXp4o0R-dAgyAPWpCI0CuQfBeSalBAUfaUG5C6rrx1W-trSX6pN474tyu3cEag8-_yHWIEsZvxxyZeq9buUlV3xP76MnNUJlX-KHO4C_ZghTFqHIukvr888Cwe8lLbMnK5tCvEPdMVc2ay17MsmCA1td482aR13Sp9k2I-_2dNVzKG5Vg78WUZUn8oIcw4Jo4FusQ91gXu3_2C1kSQJUEHPyC39BmK4cENh7dbD9ffcBi7nMvQqrSvUY6_phM8fso6vH-BeWIsqAL25IlXfJ_-SuWrC4tYnt2coBEk67bMlIMxkORFZHvnLFBQ340qtm6eS_Mx14-hpojs-KYcJKEw";

        RSAKeyProvider keyProvider = new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String keyId) {
                if (keyId.equals("69aabca3-73ba-4361-82d5-9d750745de8c")) {
                    try {
                        byte[] modulusBytes = Base64.getUrlDecoder().decode("kjJXuywWfbliR5p4j8-RenmPmkfIdzacVs27p8m_kypDo3CT0i_C6aqrkKW1vH6_TpwPxwf2ALyZk9gSW3xG3L6N0OU9H9uegCtZp3UupF1UfkYkachDI7w0WNRAJnIcHpKXgSOcBM2RWURbAusLXHEcSH9gZBeB4d-amLAhYDwMgcWREyy7O0CVouL7dDSdAMwIyKLqwRKGvFzgxKMlkDHAO82CpCDWYyNcBzcmO6l1rhgR0lO-f1KqTluNJzGg9nRM9FD9bvUFiuj4ZVEzA5WjsHulQaDN5IC_Q_5Roq3I8aVuyCCmKL3gZe3t1NgWhP_c1PJeFOxWEwTSZEd0IQ");
                        byte[] exponentBytes = Base64.getUrlDecoder().decode("AQAB");
                        RSAPublicKeySpec spec = new RSAPublicKeySpec(
                                new BigInteger(1, modulusBytes),
                                new BigInteger(1, exponentBytes)
                        );
                        KeyFactory factory = KeyFactory.getInstance("RSA");
                        return (RSAPublicKey) factory.generatePublic(spec);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                return null;
            }
            @Override
            public RSAPrivateKey getPrivateKey() {
                return null;
            }
            @Override
            public String getPrivateKeyId() {
                return null;
            }
        };

        // Verify the JWT signature using the RSA public key
        Algorithm algorithm = Algorithm.RSA256(keyProvider);
        Verification verifier = JWT.require(algorithm);
        JWTVerifier jwtVerifier = verifier.build();


        DecodedJWT verify = jwtVerifier.verify(token);
        System.out.println(verify);
    }

}
