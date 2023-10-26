package com.test.filter;

import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author xin.li
 * @since 2023/10/20 15:41:26
 */
public class StateTokenAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private String stateTokenParameter = "x-state-token";

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!request.getMethod().equals(HttpMethod.POST.name())) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        } else {
            String stateToken = obtainStateToken(request);

            // TODO query stateToken by mfa
            String userId = "e2c1378a-72d3-4904-8ca1-3b0d57395c2d";

            UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(userId, stateToken);
            this.setDetails(request, authRequest);

            Authentication authenticate = this.getAuthenticationManager().authenticate(authRequest);

            return authenticate;
        }
    }

    @Nullable
    protected String obtainStateToken(HttpServletRequest request) {
        return request.getParameter("password");
//        return request.getHeader(this.stateTokenParameter);
    }

}
