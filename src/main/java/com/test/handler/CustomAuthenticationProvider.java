package com.test.handler;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * @author xin.li
 * @since 2023/10/18 19:23:57
 */
public class CustomAuthenticationProvider extends DaoAuthenticationProvider {

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
//        HttpServletRequest req = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
//        String stateToken = req.getParameter("state_token");

        String stateToken = authentication.getCredentials().toString();
        System.out.println(stateToken);

        if (!"111".equals(stateToken)) {
            throw new AuthenticationServiceException("state_token error");
        }
    }

}
