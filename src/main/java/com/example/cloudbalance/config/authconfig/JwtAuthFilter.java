package com.example.cloudbalance.config.authconfig;

import com.example.cloudbalance.entity.auth.SessionEntity;
import com.example.cloudbalance.service.authservice.CustomUserDetailsService;
import com.example.cloudbalance.repository.SessionRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = authHeader.substring(7);

        // Check if token is blacklisted/invalidated
        Optional<SessionEntity> sessionOpt = sessionRepository.findByAccessToken(accessToken);
        if (sessionOpt.isEmpty() || !sessionOpt.get().getIsValid()) {
            response.sendError(401, "Invalid or expired session");
            return;
        }

        String userEmail;
        try {
            userEmail = jwtService.extractUsername(accessToken);
        } catch (ExpiredJwtException e) {
            // Try to refresh token if access token is expired
            handleExpiredToken(e, request, response, filterChain);
            return;
        }

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

            if (jwtService.isTokenValid(accessToken, userEmail)) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }

    private void handleExpiredToken(ExpiredJwtException ex, HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {

        // Get refresh token from request
        String refreshToken = request.getHeader("X-Refresh-Token");

        if (refreshToken == null || refreshToken.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Access token expired. Refresh token required.");
            return;
        }

        try {
            // Verify refresh token
            String userEmail = jwtService.extractUsername(refreshToken);

            // Check if refresh token is valid in database
            Optional<SessionEntity> sessionOpt = sessionRepository.findByRefreshToken(refreshToken);
            if (sessionOpt.isEmpty() || !sessionOpt.get().getIsValid() ||
                    !sessionOpt.get().getUser().getEmail().equals(userEmail)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid refresh token");
                return;
            }

            // Generate new tokens
            String newAccessToken = jwtService.generateToken(userEmail);
            String newRefreshToken = jwtService.generateRefreshToken(userEmail);

            // Update session
            SessionEntity session = sessionOpt.get();
            session.setAccessToken(newAccessToken);
            session.setRefreshToken(newRefreshToken);
            session.setUpdatedAt(LocalDateTime.now());
            sessionRepository.save(session);
            response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + newAccessToken);
            response.setHeader("X-Refresh-Token", newRefreshToken);
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().write("Token refreshed successfully");

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid refresh token");
        }
    }
}