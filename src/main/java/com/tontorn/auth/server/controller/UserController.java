package com.tontorn.auth.server.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.stereotype.Controller;
import org.springframework.util.CollectionUtils;
import org.springframework.web.bind.annotation.*;
import org.thymeleaf.util.MapUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;

@Controller
@RequestMapping("user")
public class UserController {
    @Autowired
    private ClientDetailsService clientDetailsService;

    @Autowired
    private AuthorizationServerTokenServices tokenServices;

    @Autowired
    private TokenStore jwtTokenStore;

    @GetMapping("me")
    @ResponseBody
    public String me(String accessToken) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        OAuth2AccessToken accessToken1 = jwtTokenStore.readAccessToken(accessToken);
        OAuth2Authentication auth2Authentication = jwtTokenStore.readAuthentication(accessToken);
        return objectMapper.writeValueAsString(auth2Authentication);
    }


    @GetMapping("openId")
    @ResponseBody
    public String userInfo(String openId,@RequestParam("access_token") String token)
            throws JsonProcessingException {
        String username = "wxl";
        String password = "admin123";
        String clientId = "wxl";
        String clientSecret = "admin123";
        //获取 ClientDetails
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);

        Authentication authentication = new UsernamePasswordAuthenticationToken(username,password);
        if (clientDetails == null){
            throw new UnapprovedClientAuthenticationException("clientId 不存在"+clientId);
            //判断  方言  是否一致
        }
//        else if (!clientDetails.getClientSecret().equals( DigestUtils.md5Hex(clientSecret))){
//            throw new UnapprovedClientAuthenticationException("clientSecret 不匹配"+clientId);
//        }
//        //密码授权 模式, 组建 authentication
        TokenRequest tokenRequest = new TokenRequest(new HashMap<java.lang.String, java.lang.String>(),clientId,clientDetails.getScope(),"password");

        OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request,authentication);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(oAuth2Authentication);





         return new ObjectMapper().writeValueAsString(accessToken);
    }

    @GetMapping("/getCode")
    public String getCode(String code) throws JsonProcessingException {
  //000000000000自己逻辑，access_token
       return "redirect:http://www.baidu.com?code="+code;
    }
}
