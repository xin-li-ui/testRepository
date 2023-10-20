package com.test.handler;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Collections;

/**
 * @author xin.li
 * @since 2023/10/18 19:23:57
 */
public class CustomAuthenticationProvider extends DaoAuthenticationProvider {

//    @Override
//    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
//        HttpServletRequest req = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
//        String stateToken = req.getParameter("state_token");
////        if (!"123".equals(stateToken)) {
////            throw new AuthenticationServiceException("state_token error");
////        }
////        super.additionalAuthenticationChecks(userDetails, authentication);
//    }

}
