package com.test.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.test.bean.SysUser;
import com.test.mapper.UserMapper;
import com.test.util.JSONUtil;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
public class SysUserService implements UserDetailsService {
 
    @Resource
    private UserMapper userMapper;
 
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SysUser sysUser = userMapper.getByUsername(username);
        return sysUser;
    }

    public Map<String, Object> getUserInfoMap(String username) {

        SysUser sysUser = userMapper.getByUsername(username);
        Map<String, Object> map = new HashMap<>();


        try {
            String s = JSONUtil.toJSON(sysUser);
            map = JSONUtil.getMapper().readValue(s, new TypeReference<Map<String, Object>>() {});
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return map;

//        OidcUserInfo oidcUserInfo = OidcUserInfo.builder()
////        .name("xin.li@ui.com")
//        .givenName("First")
//        .familyName("Last")
//        .middleName("Middle")
//        .nickname("User")
//        .preferredUsername(username)
//        .profile("https://example.com/" + username)
//        .picture("https://example.com/" + username + ".jpg")
//        .website("https://example.com")
//        .email(username + "@example.com")
//        .emailVerified(true)
//        .gender("female")
//        .birthdate("1970-01-01")
//        .zoneinfo("Europe/Paris")
//        .locale("en-US")
//        .phoneNumber("+1 (604) 555-1234;ext=5678")
//        .phoneNumberVerified(false)
//        .claim("address", Collections.singletonMap("formatted", "Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance"))
//        .updatedAt("1970-01-01T00:00:00Z")
//        .build();
//        return oidcUserInfo.getClaims();
    }
}