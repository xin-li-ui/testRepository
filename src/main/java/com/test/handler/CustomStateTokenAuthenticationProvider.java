package com.test.handler;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author xin.li
 * @since 2023/10/18 19:23:57
 */
public class CustomStateTokenAuthenticationProvider implements AuthenticationProvider {


    private UserDetailsService userDetailsService;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String userId = determineUserId(authentication);
        UserDetails userDetails = this.getUserDetailsService().loadUserByUsername(userId);

        String stateToken = authentication.getCredentials().toString();

        StateTokenAuthenticationToken result = StateTokenAuthenticationToken.authenticated(userDetails, authentication.getCredentials(), null);
        result.setDetails(authentication.getDetails());
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (StateTokenAuthenticationToken.class.isAssignableFrom(authentication));
    }


    private String determineUserId(Authentication authentication) {
        return (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    protected UserDetailsService getUserDetailsService() {
        return this.userDetailsService;
    }
}