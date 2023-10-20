package com.test.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.test.filter.CustomAuthenticationFilter;
import com.test.handler.*;
import com.test.service.OidcUserInfoService;
import com.test.service.SysUserService;
import jakarta.annotation.Resource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;


@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {


    @Resource
    private SysUserService sysUserService;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, AuthenticationManager manager) throws Exception {
        //针对 Spring Authorization Server 最佳实践配置
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);


//        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(manager);

        CustomStateTokenAuthenticationProvider stateTokenAuthenticationProvider = new CustomStateTokenAuthenticationProvider();
        stateTokenAuthenticationProvider.setUserDetailsService(sysUserService);


        http
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)

                .clientAuthentication((auth) -> auth
                        .errorResponseHandler(new Oauth2FailureHandler())
                        .authenticationSuccessHandler(new Oauth2SuccessHandler())
                )
                //token 相关配置 如  /oauth2/token接口
                .tokenEndpoint((token) -> token
                        .errorResponseHandler(new Oauth2FailureHandler())
                )
                .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                        .errorResponseHandler(new Oauth2FailureHandler())
                )

                // Enable OpenID Connect 1.0
                .oidc(Customizer.withDefaults());


        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
//                        .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
                )

                .anonymous(AbstractHttpConfigurer::disable)

                .addFilterBefore(new CustomAuthenticationFilter(), SecurityContextHolderFilter.class)

                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()))

//                .authenticationManager(manager)
                .authenticationProvider(stateTokenAuthenticationProvider)


        ;

        return http.build();

    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers(
                                new AntPathRequestMatcher("/actuator/**"),
                                new AntPathRequestMatcher("/oauth2/**"),
                                new AntPathRequestMatcher("/**/*.json"),
                                new AntPathRequestMatcher("/**/*.html")
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)

//                .formLogin(formLogin -> formLogin
//                        .failureHandler(new Oauth2FailureHandler())
//                )
                .formLogin(AbstractHttpConfigurer::disable)
        ;

        return http.build();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();
        return authenticationManager;
    }

    @Bean
    public AuthenticationProvider stateTokenAuthenticationProvider() {
        CustomStateTokenAuthenticationProvider stateTokenAuthenticationProvider = new CustomStateTokenAuthenticationProvider();
        stateTokenAuthenticationProvider.setUserDetailsService(sysUserService);
        return stateTokenAuthenticationProvider;
    }


//    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("oidc-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://www.baidu.com")
                .redirectUri("http://localhost:9001/login/oauth2/code/oidc-client")
                .redirectUri("http://localhost:9001/api/login/welcome")
                .postLogoutRedirectUri("http://127.0.0.1:8080/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("message.read")
                .scope("message.write")
                .scope("all")
                // 设置 Client 需要页面审核授权
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        return new InMemoryRegisteredClientRepository(oidcClient);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer(OidcUserInfoService userInfoService) {
        return (context) -> {
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                OidcUserInfo userInfo = userInfoService.loadUser(context.getPrincipal().getName());
                if (Objects.nonNull(userInfo)) {
                    context.getClaims().claims(claims -> claims.putAll(userInfo.getClaims()));
                }
            }
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().claims((claims) -> {
                    claims.put("claim-1", "value-1");
                    claims.put("claim-2", "value-2");
                });
            }
        };
    }

    /**
     * 默认发放令牌
     *
     * @return
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

//    @Bean
//    public JWKSource<SecurityContext> jwkSource(RegisteredClientRepository registeredClientRepository) {
//        return (jwkSelector, context) -> {
//
//            RegisteredClient registeredClient = registeredClientRepository.findByClientId(context.);
//            KeyPair keyPair = generateRsaKey(); // 为每个客户端生成不同的密钥对
//            RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
//                    .privateKey(keyPair.getPrivate())
//                    .keyID(registeredClient.getClientId())
//                    .build();
//            return new JWKSet(rsaKey);
//        };
//    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.withDefaultPasswordEncoder()
//                .username("xin.li@ui.com")
//                .password("111")
//                .build();
//        return new InMemoryUserDetailsManager(userDetails);
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

}