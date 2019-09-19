package com.tontorn.auth.server.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class LoginController {
    @RequestMapping("/auth/login")
    public String loginPage(){
        return "login";
    }


}
