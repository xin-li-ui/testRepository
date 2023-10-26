//package com.test.config;
//
//import com.test.filter.CustomAuthenticationFilter;
//import com.test.filter.StateTokenAuthenticationFilter;
//import jakarta.annotation.Resource;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.web.servlet.FilterRegistrationBean;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.authentication.AuthenticationManager;
//
//@Configuration
//public class ComponentConfig {
//
////    @Resource
////    private AuthenticationManager authenticationManager;
////
////    @Bean
////    public FilterRegistrationBean<StateTokenAuthenticationFilter> internalAPIInterceptor() {
////        FilterRegistrationBean<StateTokenAuthenticationFilter> filterRegBean = new FilterRegistrationBean<>();
////        StateTokenAuthenticationFilter filter = new StateTokenAuthenticationFilter();
////        filterRegBean.setFilter(filter);
////        filterRegBean.addUrlPatterns("/api/challenge");
////        filterRegBean.setOrder(0);
////        return filterRegBean;
////    }
//
//}