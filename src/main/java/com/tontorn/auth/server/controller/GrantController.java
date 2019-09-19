package com.tontorn.auth.server.controller;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Controller
@SessionAttributes("authorizationRequest")
public class GrantController {
    @RequestMapping("/oauth/confirm_access")
    public ModelAndView getAccessConfirmation(Map<String, Object> model, HttpServletRequest request) throws Exception {
        AuthorizationRequest authorizationRequest = (AuthorizationRequest) model.get("authorizationRequest");
        ModelAndView view = new ModelAndView();
        view.setViewName("approve.html");
        view.addObject("clientId", authorizationRequest.getClientId());
        return view;
    }

    @RequestMapping("/oauth/error")
    public ModelAndView oauthError(HttpServletRequest request){
        ModelAndView view = new ModelAndView();
        Object error = request.getAttribute("error");
        // The error summary may contain malicious user input,
        // it needs to be escaped to prevent XSS
        String errorSummary;
        if (error instanceof OAuth2Exception) {
            OAuth2Exception oauthError = (OAuth2Exception) error;
          //   errorSummary = HtmlUtils.htmlEscape(oauthError.getSummary());
            errorSummary = oauthError.getSummary();
        }
        else {
            errorSummary = "Unknown error";
        }
        view.setViewName("auth_error.html");
        view.addObject("error",errorSummary);
        return view;
    }

}
