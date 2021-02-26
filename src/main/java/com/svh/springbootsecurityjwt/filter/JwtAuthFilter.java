package com.svh.springbootsecurityjwt.filter;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.svh.springbootsecurityjwt.constant.AppConstants;
import com.svh.springbootsecurityjwt.util.JwtUtil;

import org.apache.logging.log4j.util.Strings;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if(Objects.isNull(SecurityContextHolder.getContext().getAuthentication())) {
            authenticateRequest(request).ifPresent(SecurityContextHolder.getContext()::setAuthentication);
        }

        filterChain.doFilter(request, response);
    }

    private Optional<UsernamePasswordAuthenticationToken> authenticateRequest(HttpServletRequest request) {
        return getJwtFromRequest(request).filter(jwtUtil::validateJwt)
                                         .map(jwtUtil::getUsernameFromJwt)
                                         .filter(Strings::isNotBlank)
                                         .map(userDetailsService::loadUserByUsername)
                                         .map(userDetails -> createUsernamePasswordAuthenticationToken(userDetails, request));
    }

    private UsernamePasswordAuthenticationToken createUsernamePasswordAuthenticationToken(UserDetails userDetails, HttpServletRequest request) {
        final var usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return usernamePasswordAuthenticationToken;
    }

    private Optional<String> getJwtFromRequest(HttpServletRequest request) {
        final var bearerToken = request.getHeader(AppConstants.AUTHORIZATION);
        return Optional.ofNullable(bearerToken)
                       .filter(Strings::isNotBlank)
                       .filter(token->token.startsWith(AppConstants.BEARER))
                       .map(token->token.replace(AppConstants.BEARER, Strings.EMPTY));
    }
}
