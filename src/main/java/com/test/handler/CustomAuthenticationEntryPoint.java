package com.test.handler;

import com.alibaba.fastjson2.JSONObject;
import com.test.model.ChallengeResult;
import com.test.model.ReturnVO;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        // UID MFA challenge


        String requestJwtStr = obtainRequestJwtStr(request);

        ChallengeResult challengeResult = ChallengeResult.builder()
                .status(ChallengeResult.TransactionStatus.MFA_REQUIRED)
                .stateToken("222")
                .stateTokenExpiredAt(1697630375L)
                .build();
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpStatus.OK.value());
        response.getWriter().write(JSONObject.toJSONString(ReturnVO.success(challengeResult)));
        response.getWriter().flush();

    }


    @Nullable
    protected String obtainRequestJwtStr(HttpServletRequest request) {
        return request.getParameter("request");
    }
}