package com.test.config;



import com.fasterxml.jackson.databind.ObjectMapper;
import com.test.service.OidcUserInfoService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

//@Configuration
//@EnableWebSecurity
public class OidcSecurityConfig {

//    @Bean
//    @Order(2)
//    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
//            throws Exception {
//        http
//                .authorizeHttpRequests((authorize) -> authorize
//                        .requestMatchers(new AntPathRequestMatcher("/actuator/**"),
//                                new AntPathRequestMatcher("/oauth2/**"),
//                                new AntPathRequestMatcher("/**/*.json"),
//                                new AntPathRequestMatcher("/**/*.html")).permitAll()
//                        .anyRequest().authenticated()
//                )
//                .cors(Customizer.withDefaults())
//                .csrf(AbstractHttpConfigurer::disable)
//                .httpBasic(Customizer.withDefaults())
//				// Form login handles the redirect to the login page from the
//				// authorization server filter chain
//                .formLogin(Customizer.withDefaults())
//
//        ;
//
//        return http.build();
//    }



//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer(OidcUserInfoService userInfoService) {
//        return (context) -> {
//            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
//                OidcUserInfo userInfo = userInfoService.loadUser(context.getPrincipal().getName());
//                context.getClaims().claims(claims -> claims.putAll(userInfo.getClaims()));
//            }

//            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
//                context.getClaims().claims((claims) -> {
//                    claims.put("claim-1", "value-1");
//                    claims.put("claim-2", "value-2");
//                });
//            }
//        };
//    }


//    @Bean
//    public OidcUserService oidcUserService() {
//        return new OidcUserService() {
//            @Override
//            public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
//                OidcUser user = super.loadUser(userRequest);
//
//                // 处理用户信息，如保存到数据库或进行其他操作
//
//                return user;
//            }
//        };
//    }





}

