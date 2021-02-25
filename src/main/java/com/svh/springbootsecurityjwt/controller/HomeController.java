package com.svh.springbootsecurityjwt.controller;

import com.svh.springbootsecurityjwt.annotation.LoggedInUser;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping
    public String home(@LoggedInUser User loggedInUser) {
        return  String.format("Any logged in user can access.. {%s}", loggedInUser.getUsername());
    }

    @GetMapping("admin")
    public String admin(@LoggedInUser User loggedInUser) {
        return  String.format("Any logged in user having role ROLE_ADMIN can access.. {%s}", loggedInUser.getUsername());
    }

    @GetMapping("user")
    public String user(@LoggedInUser User loggedInUser) {
        return  String.format("Any logged in user having role ROLE_USER or ROLE_ADMIN can access.. {%s}", loggedInUser.getUsername());
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("preAdmin")
    public String preAdmin(@LoggedInUser User loggedInUser) {
        return  String.format("Any logged in user having role ROLE_ADMIN can access.. {%s}", loggedInUser.getUsername());
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping("preUser")
    public String preUser(@LoggedInUser User loggedInUser) {
        return  String.format("Any logged in user having role ROLE_USER or ROLE_ADMIN can access.. {%s}", loggedInUser.getUsername());
    }

}
