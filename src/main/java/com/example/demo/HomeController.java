package com.example.demo;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import java.time.LocalDateTime;

@Controller
public class HomeController {

    @RequestMapping("/")
    public String home(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
        model.addAttribute("name", principal.getName());
        model.addAttribute("emailAddress", principal.getFirstAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"));
        model.addAttribute("userAttributes", principal.getAttributes());
        return "home";
    }

    @RequestMapping("/now")
    public String now(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
        //model.addAttribute("name", principal.getName());
        model.addAttribute("time", LocalDateTime.now());
        return "time";
    }

}
