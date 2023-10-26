package com.test.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.test.filter.StateTokenAuthenticationFilter;
import com.test.handler.CustomAuthenticationEntryPoint;
import com.test.handler.CustomAuthenticationProvider;
import com.test.handler.Oauth2FailureHandler;
import com.test.service.SysUserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import javax.annotation.Resource;
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
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                .clientAuthentication((auth) -> auth
//                        .errorResponseHandler(new Oauth2FailureHandler())
//                        .authenticationSuccessHandler(new Oauth2SuccessHandler())
//                )
//                .tokenEndpoint((token) -> token
//                        .errorResponseHandler(new Oauth2FailureHandler())
//                )
//                .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
//                        .errorResponseHandler(new Oauth2FailureHandler())
//                )
                .oidc(Customizer.withDefaults());

        http
                .exceptionHandling((exceptions) -> exceptions
                                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
//                        .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
                )
////                .anonymous(AbstractHttpConfigurer::disable)
////                .authenticationProvider(stateTokenAuthenticationProvider)
//
//                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
        ;
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers(
                                new AntPathRequestMatcher("/oauth2/**"),
                                new AntPathRequestMatcher("/**/*.json"),
                                new AntPathRequestMatcher("/**/*.html")
//                                new AntPathRequestMatcher("/**")
                        ).permitAll()
                        .anyRequest().authenticated()
                )
//                .httpBasic(Customizer.withDefaults())
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .addFilterBefore(stateTokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
//                .formLogin(Customizer.withDefaults())
//                .formLogin(formLogin -> formLogin
//                        .usernameParameter("user_id")
//                        .passwordParameter("state_token")
//                        .loginProcessingUrl("/api/challenge")
////                        .failureHandler(new Oauth2FailureHandler())
//                )
                .formLogin(AbstractHttpConfigurer::disable)
        ;


        return http.build();
    }

//    @Bean
//    WebSecurityCustomizer webSecurityCustomizer() {
//        return web -> web.ignoring().requestMatchers("/api/v1/admin");
//    }

    @Bean
    public StateTokenAuthenticationFilter stateTokenAuthenticationFilter() {
        StateTokenAuthenticationFilter filter = new StateTokenAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager());
        filter.setSecurityContextRepository(new HttpSessionSecurityContextRepository());
//        filter.setFilterProcessesUrl("/api/challenge");
//        filter.setAuthenticationFailureHandler(new Oauth2FailureHandler());
        return filter;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        // AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();
        CustomAuthenticationProvider customAuthenticationProvider = new CustomAuthenticationProvider();
        customAuthenticationProvider.setUserDetailsService(sysUserService);
        customAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        ProviderManager pm = new ProviderManager(customAuthenticationProvider);
        return pm;
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }


//    @Bean
//    public AuthenticationProvider stateTokenAuthenticationProvider() {
//        // 验证 state token
//        CustomAuthenticationProvider stateTokenAuthenticationProvider = new CustomAuthenticationProvider();
//        stateTokenAuthenticationProvider.setUserDetailsService(sysUserService);
//        return stateTokenAuthenticationProvider;
//    }


//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer(OidcUserInfoService userInfoService) {
//        return (context) -> {
//            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
//                OidcUserInfo userInfo = userInfoService.loadUser(context.getPrincipal().getName());
//                if (Objects.nonNull(userInfo)) {
//                    context.getClaims().claims(claims -> claims.putAll(userInfo.getClaims()));
//                }
//            }
//            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
//                context.getClaims().claims((claims) -> {
//                    claims.put("claim-1", "value-1");
//                    claims.put("claim-2", "value-2");
//                });
//            }
//        };
//    }


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