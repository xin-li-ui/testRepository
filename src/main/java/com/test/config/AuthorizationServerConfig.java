//package com.test.config;
//
//import com.nimbusds.jose.jwk.JWKSet;
//import com.nimbusds.jose.jwk.RSAKey;
//import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
//import com.nimbusds.jose.jwk.source.JWKSource;
//import com.nimbusds.jose.proc.SecurityContext;
//import com.test.handler.Oauth2FailureHandler;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
//import org.springframework.http.MediaType;
//import org.springframework.jdbc.core.JdbcTemplate;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
//import org.springframework.security.oauth2.jwt.JwtDecoder;
//import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
//import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
//import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
//import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
//
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.interfaces.RSAPrivateKey;
//import java.security.interfaces.RSAPublicKey;
//import java.util.UUID;
//
//
//@Configuration
//public class AuthorizationServerConfig {
//
//    @Bean
//    @Order(1)
//    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//        //针对 Spring Authorization Server 最佳实践配置
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//        http
//                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                // Enable OpenID Connect 1.0
//                .oidc(Customizer.withDefaults())
//
//                .clientAuthentication((auth) -> auth.errorResponseHandler(new Oauth2FailureHandler()))
//                .tokenEndpoint((token) -> token.errorResponseHandler(new Oauth2FailureHandler()))
//        ;
//
//        http
//                .cors(AbstractHttpConfigurer::disable)
//                // Redirect to the login page when not authenticated from the
//                // authorization endpoint
//                .exceptionHandling((exceptions) -> exceptions
//                        .defaultAuthenticationEntryPointFor(
//                                new LoginUrlAuthenticationEntryPoint("/login"),
//                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
//                        )
//                )
//                // Accept access tokens for User Info and/or Client Registration
//                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));
//
//        return http.build();
//
//
////        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
////        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
////
////        Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = (context) -> {
////            OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
////            JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
////            return new OidcUserInfo(principal.getToken().getClaims());
////        };
////
////        authorizationServerConfigurer.oidc((oidc) ->
////                oidc.userInfoEndpoint(
////                        (userInfo) -> userInfo.userInfoMapper(userInfoMapper)
////                )
////        );
////        http
////                .securityMatcher(endpointsMatcher)
////                .authorizeHttpRequests((authorize) -> authorize
////                        .anyRequest().authenticated()
////                )
////                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
////                .oauth2ResourceServer(resourceServer -> resourceServer
////                        .jwt(Customizer.withDefaults())
////                )
////                .exceptionHandling((exceptions) -> exceptions
////                        .defaultAuthenticationEntryPointFor(
////                                new LoginUrlAuthenticationEntryPoint("/login"),
////                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
////                        )
////                )
////                .apply(authorizationServerConfigurer);
////
////        return http.build();
//    }
//
////    @Bean
////    public RegisteredClientRepository registeredClientRepository() {
////        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
////                .clientId("oidc-client")
////                .clientSecret("{noop}secret")
////                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
////                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
////                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
////                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
////                .redirectUri("http://www.baidu.com")
////                .redirectUri("http://localhost:9001/login/oauth2/code/oidc-client")
////                .redirectUri("http://localhost:9001/api/login/welcome")
////                .postLogoutRedirectUri("http://127.0.0.1:8080/")
////                .scope(OidcScopes.OPENID)
////                .scope(OidcScopes.PROFILE)
////                .scope("message.read")
////                .scope("message.write")
////                .scope("all")
////                // 设置 Client 需要页面审核授权
////                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
////                .build();
////
////        return new InMemoryRegisteredClientRepository(oidcClient);
////    }
////
////    @Bean
////    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
////        return (context) -> {
////            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
////                context.getClaims().claims((claims) -> {
////                    claims.put("claim-1", "value-1");
////                    claims.put("claim-2", "value-2");
////                });
////            }
////        };
////    }
//
//
//    /**
//     * 注册客户端
//     * @param jdbcTemplate
//     * @return
//     */
//    @Bean
//    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
//        return new JdbcRegisteredClientRepository(jdbcTemplate);
//    }
//
//
//    /**
//     * 授权
//     * @param jdbcTemplate
//     * @param registeredClientRepository
//     * @return
//     */
//    @Bean
//    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
//        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
//    }
//
//
//
//    /**
//     * 默认发放令牌
//     * @return
//     */
//    @Bean
//    public JWKSource<SecurityContext> jwkSource() {
//        KeyPair keyPair = generateRsaKey();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//        RSAKey rsaKey = new RSAKey.Builder(publicKey)
//                .privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return new ImmutableJWKSet<>(jwkSet);
//    }
//
//    private static KeyPair generateRsaKey() {
//        KeyPair keyPair;
//        try {
//            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//            keyPairGenerator.initialize(2048);
//            keyPair = keyPairGenerator.generateKeyPair();
//        }
//        catch (Exception ex) {
//            throw new IllegalStateException(ex);
//        }
//        return keyPair;
//    }
//
//    @Bean
//    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
//    }
//
//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder().build();
//    }
//}