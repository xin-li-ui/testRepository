package com.test.handler;

import com.alibaba.fastjson2.JSONObject;
import com.test.model.ChallengeResult;
import com.test.model.ReturnVO;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

import java.io.IOException;

public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        // UID MFA challenge

        ChallengeResult challengeResult = ChallengeResult.builder()
                .status(ChallengeResult.TransactionStatus.MFA_REQUIRED)
                .stateToken("10dfec0a0f9d458087e192f05362cc73")
                .stateTokenExpiredAt(1697630375L)
                .build();
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpStatus.OK.value());
        response.getWriter().write(JSONObject.toJSONString(ReturnVO.success(challengeResult)));
        response.getWriter().flush();

    }
}