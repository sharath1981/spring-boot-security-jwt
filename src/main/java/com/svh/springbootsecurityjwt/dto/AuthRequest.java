package com.svh.springbootsecurityjwt.dto;

import lombok.Data;

@Data
public class AuthRequest {
    private String username;
    private String password;
}
