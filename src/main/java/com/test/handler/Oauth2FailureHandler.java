package com.test.handler;

import com.alibaba.fastjson2.JSONObject;
import com.test.model.ReturnVO;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class Oauth2FailureHandler implements AuthenticationFailureHandler {


    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String message;
        if (exception instanceof OAuth2AuthenticationException auth2AuthenticationException) {
            OAuth2Error error = auth2AuthenticationException.getError();
            message = "认证信息错误：" + error.getErrorCode() + error.getDescription();
        } else {
            message = exception.getMessage();
        }

        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpStatus.OK.value());
        response.getWriter().write(JSONObject.toJSONString(ReturnVO.failed(401, message)));
        response.getWriter().flush();

    }
}