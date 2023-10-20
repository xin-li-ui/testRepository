package com.test.config;

import com.test.filter.CustomAuthenticationFilter;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;

@Configuration
public class ComponentConfig {

//    @Resource
//    private AuthenticationManager authenticationManager;
//
//    @Bean
//    public FilterRegistrationBean<CustomAuthenticationFilter> internalAPIInterceptor() {
//        FilterRegistrationBean<CustomAuthenticationFilter> filterRegBean = new FilterRegistrationBean<>();
//        CustomAuthenticationFilter filter = new CustomAuthenticationFilter(authenticationManager);
//        filterRegBean.setFilter(filter);
//        filterRegBean.addUrlPatterns("/challenge");
//        filterRegBean.setOrder(500);
//        return filterRegBean;
//    }

}