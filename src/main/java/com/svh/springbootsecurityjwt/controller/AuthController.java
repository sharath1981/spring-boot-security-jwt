package com.svh.springbootsecurityjwt.controller;

import javax.servlet.http.HttpServletResponse;

import com.svh.springbootsecurityjwt.constant.AppConstants;
import com.svh.springbootsecurityjwt.dto.AuthRequest;
import com.svh.springbootsecurityjwt.util.JwtUtil;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Log4j2
@RequiredArgsConstructor
@RestController
public class AuthController {

    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    @PostMapping("login")
    public String authenticate(@RequestBody AuthRequest authRequest, HttpServletResponse response) throws Exception {
        try {
            final var authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception ex) {
            log.error("AUTHENTICATION FAILED... {} ", ex.getMessage());
            throw new Exception(ex.getMessage());
        }
        final var jwt = jwtUtil.generateJwt(authRequest.getUsername());
        final var authorizationHeader = String.format("Bearer %s", jwt);
        response.addHeader(AppConstants.AUTHORIZATION, authorizationHeader);
        
        return authorizationHeader;
    }

}
