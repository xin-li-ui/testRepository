//package com.test.handler;
//
//import com.alibaba.fastjson2.JSONObject;
//import com.test.model.ReturnVO;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.http.HttpStatus;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
//import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//import org.springframework.stereotype.Component;
//
//import java.io.IOException;
//
//@Component
//public class Oauth2SuccessHandler implements AuthenticationSuccessHandler {
//
//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
//
//        response.setContentType("application/json;charset=UTF-8");
//        response.setStatus(HttpStatus.OK.value());
//        response.getWriter().write(JSONObject.toJSONString(ReturnVO.success(authentication.getPrincipal())));
//        response.getWriter().flush();
//    }
//}