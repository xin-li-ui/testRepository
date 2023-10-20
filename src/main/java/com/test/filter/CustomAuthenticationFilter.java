package com.test.filter;


import com.test.handler.StateTokenAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class CustomAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/login", "GET");

    private String stateTokenParameter = "state_token";

    public CustomAuthenticationFilter() {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        String stateToken = obtainStateToken(request);
        String userId = "e2c1378a-72d3-4904-8ca1-3b0d57395c2d";

        StateTokenAuthenticationToken authRequest = StateTokenAuthenticationToken.unauthenticated(userId, stateToken);
        this.setDetails(request, authRequest);
        return this.getAuthenticationManager().authenticate(authRequest);
    }


    private String obtainStateToken(HttpServletRequest request) {
        return request.getParameter(this.stateTokenParameter);
    }


    protected void setDetails(HttpServletRequest request, StateTokenAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }

//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//
//        if (!DEFAULT_ANT_PATH_REQUEST_MATCHER.matches(request)) {
//            filterChain.doFilter(request, response);
//            return;
//        }
////        String req = request.getParameter("request");
////        String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
////        String responseType = request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE);
////        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
////        String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);
//
////        String clientSecret = "5iDW48UV8EVhzHC3F4zmQciykLu2XL25JkNKKgHv";
////
////        DecodedJWT decodedJwt = JwtUtils.validateJwtForAuthUrl(req, clientId, clientSecret, scope, responseType, redirectUri);
////        RequestParams requestParams = JwtUtils.transformDecodedJwtToRequestParams(decodedJwt);
//
////        String stateToken = requestParams.getStateToken();
//
////        String workspaceId = "adf61650-853a-4fc8-b89d-7f872a72d86b";
////        String userId = "e2c1378a-72d3-4904-8ca1-3b0d57395c2d";
//
//
//
//
////        String accessToken = tokenService.generateAccessToken(user);
////        String idToken = tokenService.generateIdToken(user);
//
//
//        String stateToken = "123";
//        String username = "xin.li@ui.com";
//        List<GrantedAuthority> authorities = new ArrayList<>();
//        authorities.add(new SimpleGrantedAuthority("SCOPE_" + OidcScopes.OPENID));
//
//        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(username, "111", authorities);
//        Authentication authenticated = this.authenticationManager.authenticate(authentication);
//        SecurityContextHolder.getContext().setAuthentication(authenticated);
//        filterChain.doFilter(request, response);
//    }
}