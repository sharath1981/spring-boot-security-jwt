package com.svh.springbootsecurityjwt.util;

import java.util.Date;
import java.util.HashMap;
import java.util.Optional;
import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

import com.svh.springbootsecurityjwt.constant.AppConstants;

import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Log4j2
@RequiredArgsConstructor
@Component
public class JwtUtil {

    @Value("${jwt.secretkey}")
    private String jwtSecretkey;

    public String getUsernameFromJwt(String jwt) {
        return getClaimFromJwt(jwt, Claims::getSubject);
    }

    public <T> T getClaimFromJwt(String jwt, Function<Claims, T> claimsResolver) {
        final var claims = getAllClaimsFromJwt(jwt);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromJwt(String jwt) {
        return Jwts.parser()
                   .setSigningKey(jwtSecretkey)
                   .parseClaimsJws(jwt)
                   .getBody();
    }

    public String generateJwt(String subject) {
        final var claims = new HashMap<String, Object>();
        return Jwts.builder()
                   .setClaims(claims)
                   .setSubject(subject)
                   .setIssuedAt(new Date(System.currentTimeMillis()))
                   .setExpiration(new Date(System.currentTimeMillis() + AppConstants.JWT_VALIDITY))
                   .signWith(SignatureAlgorithm.HS256, jwtSecretkey)
                   .compact();
    }

    public Boolean validateJwt(String jwt) {
        try {
            getAllClaimsFromJwt(jwt);
            return isJwtBlacklisted(jwt);
        } catch (SignatureException ex) {
            log.error("Invalid JWT signature... {}", ex.getMessage());
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token... {}", ex.getMessage());
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token... {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token... {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty... {}", ex.getMessage());
        }
        return Boolean.FALSE;
    }

    public Boolean isJwtBlacklisted(String jwt) {
        //TODO: add blacklisted jwt condition, retrieve jwt from redis cache to verify will help in logout
        return Boolean.TRUE;
    }

	public Optional<String> getJwtFromRequest(HttpServletRequest request) {
	    final var bearerToken = request.getHeader(AppConstants.AUTHORIZATION);
	    return Optional.ofNullable(bearerToken)
	                   .filter(Strings::isNotBlank)
	                   .filter(token->token.startsWith(AppConstants.BEARER))
	                   .map(token->token.replace(AppConstants.BEARER, Strings.EMPTY));
	}

}
