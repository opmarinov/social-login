package com.login.sociallogin.security.resources;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserInfo {

    @RequestMapping("/user")
    public Principal user(Principal principal) {
        return principal;
    }
}
