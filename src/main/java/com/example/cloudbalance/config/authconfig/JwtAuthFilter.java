package com.example.cloudbalance.config.authconfig;

import com.example.cloudbalance.entity.auth.SessionEntity;
import com.example.cloudbalance.service.authservice.CustomUserDetailsService;
import com.example.cloudbalance.repository.SessionRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.ExpiredJwtException;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Optional;
@Slf4j
@Component
public class JwtAuthFilter extends OncePerRequestFilter {


    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;
    private final SessionRepository sessionRepository;

    public JwtAuthFilter(JwtService jwtService, CustomUserDetailsService userDetailsService, SessionRepository sessionRepository) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.sessionRepository = sessionRepository;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return path.startsWith("/auth/refresh");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        log.info("Processing request with Authorization header: {}", authHeader);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.debug("No valid Bearer token found, continuing filter chain");
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = authHeader.substring(7);
        log.info("Access token: {}", accessToken);

        // First check if the session is valid in the database
        Optional<SessionEntity> sessionOpt = sessionRepository.findByAccessToken(accessToken);
        if (sessionOpt.isEmpty() || !sessionOpt.get().getIsValid()) {
            log.warn("Invalid or expired session for token: {}", accessToken);
            response.sendError(401, "Invalid or expired session");
            return;
        }

        // Now try to extract username and validate the token
        String userEmail;
        try {
            userEmail = jwtService.extractUsername(accessToken);
            log.info("Extracted userEmail: {}", userEmail);

            // Check token validity (including expiration)
            if (!jwtService.isTokenValid(accessToken, userEmail)) {
                log.warn("Token validation failed for user: {}", userEmail);
                // Invalidate the session since the token is expired
                SessionEntity session = sessionOpt.get();
                session.setIsValid(false);
                session.setUpdatedAt(LocalDateTime.now());
                sessionRepository.save(session);

                handleExpiredToken(request, response, filterChain);
                return;
            }

            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authToken);
                log.info("Authentication set for user: {}", userEmail);
            }
        } catch (ExpiredJwtException e) {
            log.warn("Access token expired: {}", accessToken);
            // Invalidate the session since the token is expired
            SessionEntity session = sessionOpt.get();
            session.setIsValid(false);
            session.setUpdatedAt(LocalDateTime.now());
            sessionRepository.save(session);

            handleExpiredToken(request, response, filterChain);
            return;
        } catch (Exception e) {
            log.error("Error processing JWT token: {}", e.getMessage());
            response.sendError(401, "Invalid token");
            return;
        }

        filterChain.doFilter(request, response);
    }
    private void handleExpiredToken(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {
        String refreshToken = request.getHeader("X-Refresh-Token");
        log.info("Handling expired token, refresh token: {}", refreshToken);

        if (refreshToken == null || refreshToken.isEmpty()) {
            log.warn("No refresh token provided for expired token");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Access token expired. Refresh token required.");
            return;
        }

        try {
            String userEmail = jwtService.extractUsername(refreshToken);
            log.info("Extracted userEmail from refresh token: {}", userEmail);

            Optional<SessionEntity> sessionOpt = sessionRepository.findByRefreshToken(refreshToken);
            if (Boolean.TRUE.equals(sessionOpt.isEmpty() || !sessionOpt.get().getIsValid()) ||
                    !sessionOpt.get().getUser().getEmail().equals(userEmail)) {
                log.warn("Invalid or non-existent session for refresh token");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid refresh token");
                return;
            }

            // Validate refresh token
            if (!jwtService.isTokenValid(refreshToken, userEmail)) {
                log.warn("Refresh token expired or invalid: {}", refreshToken);
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Refresh token expired or invalid");
                return;
            }

            // Generate new tokens
            String newAccessToken = jwtService.generateToken(userEmail);
            String newRefreshToken = jwtService.generateRefreshToken(userEmail);
            log.info("Generated new access token: {}", newAccessToken);

            // Invalidate old session
            SessionEntity oldSession = sessionOpt.get();
            oldSession.setIsValid(false);
            oldSession.setUpdatedAt(LocalDateTime.now());
            sessionRepository.save(oldSession);
            log.info("Invalidated old session for user: {}", userEmail);

            // Create new session
            SessionEntity newSession = SessionEntity.builder()
                    .user(oldSession.getUser())
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .isValid(true)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build();
            sessionRepository.save(newSession);
            log.info("Created new session for user: {}", userEmail);

            // Add tokens to response headers
            response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + newAccessToken);
            response.setHeader("X-Refresh-Token", newRefreshToken);

            // Update SecurityContextHolder with new authentication
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authToken);
            log.info("Updated SecurityContextHolder for user: {}", userEmail);

            // Continue the filter chain
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            log.error("Error processing refresh token: {}", e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid refresh token");
        }
    }
}