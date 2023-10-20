//package com.test.util;
//
//import com.auth0.jwt.JWT;
//import com.auth0.jwt.algorithms.Algorithm;
//import com.auth0.jwt.exceptions.JWTVerificationException;
//import com.auth0.jwt.interfaces.DecodedJWT;
//import com.auth0.jwt.interfaces.JWTVerifier;
//import com.test.model.RequestParams;
//import lombok.extern.slf4j.Slf4j;
//
//import java.security.SecureRandom;
//import java.time.Instant;
//import java.time.temporal.ChronoUnit;
//import java.util.Collections;
//import java.util.Date;
//import java.util.Map;
//import java.util.Objects;
//
///**
// * @author xin.li
// * @since 2023/09/28 17:47:59
// */
//@Slf4j
//public class JwtUtils {
//
//    public static final String CLIENT_ID = "DI4A9DIXGVDRLC2BEBAP";
//    public static final String CLIENT_SECRET = "5iDW48UV8EVhzHC3F4zmQciykLu2XL25JkNKKgHv";
//
//    private static final Map<String, Object> HEADERS = Collections.singletonMap("alg", "HS256");
//
//    /**
//     * create health_check client_assertion
//     * @param clientId
//     * @param clientSecret
//     * @param aud
//     * @return
//     */
//    public static String createJwt(String clientId, String clientSecret, String aud) {
//        Instant instant = Instant.now();
//        return JWT.create()
//                .withHeader(HEADERS)
//                .withIssuer(clientId)
//                .withSubject(clientId)
//                .withAudience(aud)
//                .withIssuedAt(Date.from(instant))
//                .withExpiresAt(Date.from(instant.plus(5, ChronoUnit.MINUTES)))
//                .withJWTId(generateJwtId(32))
//                .sign(Algorithm.HMAC256(clientSecret));
//    }
//
//    public static void validateJwt(String jwtToken, String clientId, String clientSecret, String aud) {
//        try {
//            Algorithm algorithm = Algorithm.HMAC256(clientSecret);
//            JWTVerifier verifier = JWT.require(algorithm)
//                    .withIssuer(clientId)
//                    .withSubject(clientId)
//                    .withAudience(aud)
//                    .build();
//
//            verifier.verify(jwtToken);
//
//        } catch (JWTVerificationException e) {
//            e.printStackTrace();
//        }
//    }
//
//
//    public static DecodedJWT validateJwtForAuthUrl(String jwtToken,
//                                                   String clientId,
//                                                   String clientSecret,
//                                                   String scope,
//                                                   String responseType,
//                                                   String redirectUri) {
//        Algorithm algorithm = Algorithm.HMAC256(clientSecret);
//        JWTVerifier verifier = JWT.require(algorithm)
//                .withClaim("scope", scope)
//                .withClaim("response_type", responseType)
//                .withClaim("client_id", clientId)
//                .withClaim("redirect_uri", redirectUri)
//                .withClaim("use_duo_code_attribute", true)
//                .build();
//        return verifier.verify(jwtToken);
//    }
//
//    public static RequestParams transformDecodedJwtToRequestParams(DecodedJWT decodedJwt) {
//        RequestParams params = new RequestParams();
//        params.setScope(decodedJwt.getClaim("scope").asString());
//        params.setClientId(decodedJwt.getClaim("client_id").asString());
//        params.setRedirectUri(decodedJwt.getClaim("redirect_uri").asString());
//        params.setState(decodedJwt.getClaim("state").asString());
//        params.setStateToken(decodedJwt.getClaim("state_token").asString());
//        params.setUidUname(decodedJwt.getClaim("uid_uname").asString());
//        params.setLoginHint(decodedJwt.getClaim("login_hint").asString());
//        params.setResponseType(decodedJwt.getClaim("response_type").asString());
//        params.setUseUidCodeAttribute(decodedJwt.getClaim("use_uid_code_attribute").asBoolean());
//        return params;
//    }
//
//
//    public static DecodedJWT decodeJwt(String jwtToken, String clientSecret) {
//        Algorithm algorithm = Algorithm.HMAC256(clientSecret);
//        JWTVerifier verifier = JWT.require(algorithm).build();
//        return verifier.verify(jwtToken);
//    }
//
//
//
//
//    static String generateJwtId(Integer length) {
//        SecureRandom secureRandom = new SecureRandom();
//        StringBuilder sb = new StringBuilder();
//        while (sb.length() < length) {
//            sb.append(Integer.toHexString(secureRandom.nextInt()));
//        }
//        return sb.substring(0, length);
//    }
//
//
//    static String createJwtForAuthUrl(String clientId, String clientSecret) {
//        Date expiration = new Date();
//        expiration.setTime(expiration.getTime() + 3600000L);
//        return JWT.create()
//                .withHeader(Collections.singletonMap("alg", "HS256"))
//                .withExpiresAt(expiration).withClaim("scope", "openid")
//                .withClaim("client_id", clientId)
//                .withClaim("redirect_uri", "127.0.0.1:8080/callback")
//                .withClaim("state", "4568711fgfg12121454545")
//                .withClaim("duo_uname", "xin.li@ui.com")
//                .withClaim("login_hint", "xin.li@ui.com")
//                .withClaim("response_type", "code")
//                .withClaim("use_duo_code_attribute", true)
//                .sign(Algorithm.HMAC256(clientSecret));
//    }
//
//    public static void main(String[] args) throws InterruptedException {
////        String jwtToken = "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAicW5oR0VIZ0h3d1FwdDFjR0FwM1U5MjVJSnhjTjRDamZLQmJQeWRHWVFZQT0iLCAiamt1IjogImh0dHBzOi8vYXBpLWVjOTNmMWNkLmR1b3NlY3VyaXR5LmNvbS9mcmFtZS9ESTRBOURJWEdWRFJMQzJCRUJBUC8ud2VsbC1rbm93bi9qd2tzLmpzb24ifQ.eyJpc3MiOiAiaHR0cHM6Ly9hcGktZWM5M2YxY2QuZHVvc2VjdXJpdHkuY29tL29hdXRoL3YxL3Rva2VuIiwgInN1YiI6ICJ4aW4ubGlAdWkuY29tIiwgImF1ZCI6ICJESTRBOURJWEdWRFJMQzJCRUJBUCIsICJleHAiOiAxNjk2NjUyMTkwLCAiaWF0IjogMTY5NjY0ODYwMiwgImF1dGhfdGltZSI6IDE2OTY2NDg1OTAsICJhdXRoX3Jlc3VsdCI6IHsicmVzdWx0IjogImFsbG93IiwgInN0YXR1cyI6ICJhbGxvdyIsICJzdGF0dXNfbXNnIjogIkxvZ2luIFN1Y2Nlc3NmdWwifSwgImF1dGhfY29udGV4dCI6IHsidHhpZCI6ICIyMTcxYjNmNi02YmVmLTQ5MDktYTJiOC0xOWU5NGNiZjVlYmQiLCAidGltZXN0YW1wIjogMTY5NjY0ODU5MCwgInVzZXIiOiB7Im5hbWUiOiAieGluLmxpQHVpLmNvbSIsICJrZXkiOiAiRFU3R0hUR0hDTDY5WDVRWVI0N04iLCAiZ3JvdXBzIjogW119LCAiYXBwbGljYXRpb24iOiB7Im5hbWUiOiAiT2t0YSIsICJrZXkiOiAiREk0QTlESVhHVkRSTEMyQkVCQVAifSwgImF1dGhfZGV2aWNlIjogeyJpcCI6IG51bGwsICJsb2NhdGlvbiI6IHsiY2l0eSI6IG51bGwsICJzdGF0ZSI6IG51bGwsICJjb3VudHJ5IjogbnVsbH0sICJuYW1lIjogIldBMkdUMFFEWDBNNVZXNTY0QVRCIiwgImtleSI6ICJXQTJHVDBRRFgwTTVWVzU2NEFUQiJ9LCAiYWNjZXNzX2RldmljZSI6IHsiaXAiOiAiMjE4LjEwMi4xMTUuMTgiLCAibG9jYXRpb24iOiB7ImNpdHkiOiAiQ2VudHJhbCIsICJzdGF0ZSI6ICJDZW50cmFsIGFuZCBXZXN0ZXJuIERpc3RyaWN0IiwgImNvdW50cnkiOiAiSG9uZyBLb25nIn0sICJob3N0bmFtZSI6IG51bGwsICJlcGtleSI6ICJFUDNOT1FYVzNBOFk1SktHVlVVViIsICJvcyI6ICJNYWMgT1MgWCIsICJvc192ZXJzaW9uIjogIjEyLjAuMSIsICJicm93c2VyIjogIkVkZ2UgQ2hyb21pdW0iLCAiYnJvd3Nlcl92ZXJzaW9uIjogIjExNy4wLjIwNDUuMzUiLCAiZmxhc2hfdmVyc2lvbiI6ICJ1bmluc3RhbGxlZCIsICJqYXZhX3ZlcnNpb24iOiAidW5pbnN0YWxsZWQiLCAiaXNfZW5jcnlwdGlvbl9lbmFibGVkIjogInVua25vd24iLCAiaXNfZmlyZXdhbGxfZW5hYmxlZCI6ICJ1bmtub3duIiwgImlzX3Bhc3N3b3JkX3NldCI6ICJ1bmtub3duIn0sICJmYWN0b3IiOiAiV2ViQXV0aG4gQ2hyb21lIFRvdWNoIElEIiwgImV2ZW50X3R5cGUiOiAiYXV0aGVudGljYXRpb24iLCAicmVzdWx0IjogInN1Y2Nlc3MiLCAicmVhc29uIjogInVzZXJfYXBwcm92ZWQiLCAiYWxpYXMiOiAiIiwgImlzb3RpbWVzdGFtcCI6ICIyMDIzLTEwLTA3VDAzOjE2OjMwLjcxOTE5MyswMDowMCIsICJlbWFpbCI6ICIiLCAib29kX3NvZnR3YXJlIjogbnVsbCwgImFkYXB0aXZlX3RydXN0X2Fzc2Vzc21lbnRzIjogeyJtb3JlX3NlY3VyZV9hdXRoIjogeyJmZWF0dXJlc192ZXJzaW9uIjogIjMuMCIsICJtb2RlbF92ZXJzaW9uIjogIjIwMjIuMDcuMTkuMDAxIiwgInBvbGljeV9lbmFibGVkIjogZmFsc2UsICJyZWFzb24iOiAiTm9ybWFsIGxldmVsIG9mIHRydXN0OyBubyBkZXRlY3Rpb24gb2Yga25vd24gYXR0YWNrIHBhdHRlcm4iLCAidHJ1c3RfbGV2ZWwiOiAiTk9STUFMIn0sICJyZW1lbWJlcl9tZSI6IHsiZmVhdHVyZXNfdmVyc2lvbiI6ICIzLjAiLCAibW9kZWxfdmVyc2lvbiI6ICIyMDIyLjA3LjE5LjAwMSIsICJwb2xpY3lfZW5hYmxlZCI6IGZhbHNlLCAicmVhc29uIjogIktub3duIEFjY2VzcyBJUCIsICJ0cnVzdF9sZXZlbCI6ICJOT1JNQUwifX0sICJ0cnVzdGVkX2VuZHBvaW50X3N0YXR1cyI6ICJ1bmtub3duIn0sICJwcmVmZXJyZWRfdXNlcm5hbWUiOiAieGluLmxpQHVpLmNvbSJ9.bhY5lbGHVA7ppLB48qc9sSfk8nlfNP5-KyEoO7Lp13xb-I44Ly96iKJna6hnxEW6LdJbGp_8lvv4HENDU6AAT9iLsSxicO3GGf8VL_JsDFvEiwlNyow2YrEuHdxZRK7quieKpAbbo_ckD2tGtg3gyAnDt6VICNP8XUI8ZtrLWknHHUuAkpzivqPfZ1S6iIYnCBobvGRtC7lG6PNeKm2gVDM4bSwAxm5_rvmSzHL_m3lVj2cj-gZXLV1scirawsjtxvBHI6fpEIDCd6AnSlauODY-93yRK46KFzCHtd5mGMmGsR12OINKfVqA5Zv3B5mVtiV7lQxRKzQ2bGG58d3hJ4HkQCJPklsDuK8VEEjlha42GqtPDgwzg9H0qbrN2vEgzFn7xL9515EbWZTIMXgVdvdQl1tlii2A_GS_g5o7fkCCyObJIWtmvjBmQWyFiDGB7YvcxAgV3knATFFGQUzb5iUEZQUFV4mgKxKQRGeDT_Tn2SkIFEgLCq6NtCESezsMnXmPkX5998VYrEWWIqZWvRmNG7eCDFABqdqKkJ6496EHwC8SL5DBimbOXWPYnejL0pc2zvK-55sFRuqJinYKvmVFEZzFbnVxgohfVWxZDLK02bxys0MJPosiH7nQbqqw6t6C-ghFQRM6_oa2LsciMgLODl5Xpi-LGum03oeis5A";
//
//
////        String jwt = createJwt(CLIENT_ID, CLIENT_ID, AUD);
////        System.out.println(jwt);
////
////        Thread.sleep(5000);
////
////        validateJwt(jwt, CLIENT_ID, CLIENT_ID, AUD);
//
//
//
////        String jwtToken = createJwtForAuthUrl(clientId, clientSecret);
////        System.out.println(jwtToken);
////        System.out.println();
////
////
////        String clientSecret2 = "5iDW48UV8EVhzHC3F4zmQciykLu2XL25JkNKKgHa";
////        DecodedJWT decodedJWT = decodeJwt(jwtToken, clientSecret2);
////        System.out.println("clientId: " + decodedJWT.getClaim("client_id").asString());
////        System.out.println("redirectUri: " + decodedJWT.getClaim("redirect_uri").asString());
////        System.out.println("state: " + decodedJWT.getClaim("state").asString());
////        System.out.println("username: " + decodedJWT.getClaim("duo_uname").asString());
////        System.out.println("useDuoCodeAttribute: " + decodedJWT.getClaim("use_duo_code_attribute").asString());
//    }
//}