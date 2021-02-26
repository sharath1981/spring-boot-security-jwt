package com.svh.springbootsecurityjwt.constant;

public class AppConstants {

    public static final long JWT_VALIDITY = 5 * 60 * 60 * 1000;
	public static final String BEARER = "Bearer ";
	public static final String AUTHORIZATION = "Authorization";

	private AppConstants(){ }
    
}
