package com.example.cloudbalance.config.authconfig;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.function.Function;

@Slf4j
@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    @Value("${jwt.refreshExpiration}")
    private long refreshExpiration;

    public String extractUsername(String token) {
        String username = extractClaim(token, Claims::getSubject);
        log.debug("Extracted username from token: {}", username);
        return username;
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        try {
            final Claims claims = extractAllClaims(token);
            return claimsResolver.apply(claims);
        } catch (Exception e) {
            log.warn("Failed to extract claim from token", e);
            throw e;
        }
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
        } catch (Exception e) {
            log.error("Error parsing JWT token", e);
            throw e;
        }
    }

    public String generateToken(String username) {
        String token = createToken(username, expiration);
        log.info("Generated access token for user: {}", username);
        return token;
    }

    public String generateRefreshToken(String username) {
        String refreshToken = createToken(username, refreshExpiration);
        log.info("Generated refresh token for user: {}", username);
        return refreshToken;
    }

    private String createToken(String username, long expirationTime) {
        Date now = new Date();
        Date expiryDate = new Date(System.currentTimeMillis() + expirationTime);
        log.debug("Creating token for user: {} with expiration: {}", username, expiryDate);
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }

    public boolean isTokenValid(String token, String username) {
        try {
            final String extractedUsername = extractUsername(token);
            boolean isTokenExpired = isTokenExpired(token);
            boolean isValid = extractedUsername.equals(username) && !isTokenExpired;

            log.debug("Token validation for {}: username match: {}, not expired: {}",
                    username, extractedUsername.equals(username), !isTokenExpired);

            return isValid;
        } catch (Exception e) {
            log.warn("Token validation failed for user {}: {}", username, e.getMessage());
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        boolean expired = extractExpiration(token).before(new Date());
        log.debug("Token expired: {}", expired);
        return expired;
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}