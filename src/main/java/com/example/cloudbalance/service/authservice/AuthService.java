package com.example.cloudbalance.service.authservice;

import com.example.cloudbalance.config.authconfig.JwtService;
import com.example.cloudbalance.dto.authdto.AuthUserRequestDTO;
import com.example.cloudbalance.dto.authdto.AuthUserResponseDTO;
import com.example.cloudbalance.entity.auth.RoleEntity;
import com.example.cloudbalance.entity.auth.SessionEntity;
import com.example.cloudbalance.entity.auth.UsersEntity;
import com.example.cloudbalance.exception.CustomException;
import com.example.cloudbalance.mapper.auth.DtoToEntityMapper;
import com.example.cloudbalance.repository.RoleRepository;
import com.example.cloudbalance.repository.SessionRepository;
import com.example.cloudbalance.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Slf4j
@Service
@Transactional
public class AuthService implements IAuthService {

    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final DtoToEntityMapper dtoToEntityMapper;
    private final UserDetailsService userDetailsService;

    public AuthService(UserRepository userRepository, SessionRepository sessionRepository,
                       RoleRepository roleRepository, JwtService jwtService,
                       AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder,
                       DtoToEntityMapper dtoToEntityMapper, UserDetailsService userDetailsService) {
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.roleRepository = roleRepository;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.dtoToEntityMapper = dtoToEntityMapper;
        this.userDetailsService = userDetailsService;
    }

    public ResponseEntity<AuthUserResponseDTO> loginUser(AuthUserRequestDTO userRequest) {
        if (userRequest == null) {
            throw new CustomException("Request body cannot be null", HttpStatus.BAD_REQUEST);
        }
        String loginIdentifier = userRequest.getEmail() != null
                ? userRequest.getEmail()
                : userRequest.getUsername();
        if (loginIdentifier == null || loginIdentifier.isBlank()) {
            throw new CustomException("Email or Username must be provided", HttpStatus.BAD_REQUEST);
        }

        if (userRequest.getPassword() == null || userRequest.getPassword().isBlank()) {
            throw new CustomException("Password must be provided", HttpStatus.BAD_REQUEST);
        }

        Optional<UsersEntity> userOptional = userRequest.getEmail() != null
                ? userRepository.findByEmail(userRequest.getEmail())
                : userRepository.findByUsername(userRequest.getUsername());

        if (userOptional.isEmpty()) {
            throw new CustomException("Invalid credentials", HttpStatus.UNAUTHORIZED);
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginIdentifier,
                            userRequest.getPassword()
                    )
            );
        } catch (BadCredentialsException e) {
            throw new CustomException("Invalid credentials", HttpStatus.UNAUTHORIZED);
        } catch (AuthenticationException e) {
            throw new CustomException("Authentication failed", HttpStatus.UNAUTHORIZED);
        }

        UsersEntity user = userOptional.get();
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);

        String accessToken = jwtService.generateToken(user.getEmail());
        String refreshToken = jwtService.generateRefreshToken(user.getEmail());

        SessionEntity session = SessionEntity.builder()
                .user(user)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .isValid(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        sessionRepository.save(session);

        AuthUserResponseDTO responseDTO = new AuthUserResponseDTO(
                accessToken,
                refreshToken,
                user.getEmail(),
                user.getUsername(),
                user.getRole().getName()
        );

        return ResponseEntity.ok(responseDTO);
    }

    public ResponseEntity<String> logoutUser(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new CustomException("Access token is missing or blank", HttpStatus.BAD_REQUEST);
        }

        return sessionRepository.findByAccessToken(accessToken)
                .map(session -> {
                    session.setIsValid(false);
                    session.setUpdatedAt(LocalDateTime.now());
                    sessionRepository.save(session);
                    return ResponseEntity.ok("Logged out successfully");
                })
                .orElseThrow(() -> new CustomException("Invalid or expired access token", HttpStatus.UNAUTHORIZED));
    }

    public ResponseEntity<AuthUserResponseDTO> refreshToken(String refreshToken) {
        log.info("Refreshing token: {}", refreshToken);

        if (refreshToken == null || refreshToken.isBlank()) {
            log.warn("Refresh token is null or blank");
            throw new CustomException("Refresh token must be provided", HttpStatus.BAD_REQUEST);
        }

        String email;
        try {
            email = jwtService.extractUsername(refreshToken);
            log.info("Extracted email from refresh token: {}", email);
        } catch (Exception e) {
            log.error("Invalid refresh token format: {}", e.getMessage());
            throw new CustomException("Invalid refresh token format", HttpStatus.UNAUTHORIZED);
        }

        if (email == null || email.isBlank()) {
            log.warn("Extracted email is null or blank");
            throw new CustomException("Invalid refresh token", HttpStatus.UNAUTHORIZED);
        }

        SessionEntity oldSession = sessionRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> {
                    log.warn("Session not found for refresh token");
                    return new CustomException("Session not found for the provided refresh token", HttpStatus.UNAUTHORIZED);
                });

        if (Boolean.FALSE.equals(oldSession.getIsValid())) {
            log.warn("Refresh token session is invalidated");
            throw new CustomException("Refresh token has been invalidated", HttpStatus.UNAUTHORIZED);
        }

        if (!jwtService.isTokenValid(refreshToken, email)) {
            log.warn("Refresh token is expired or invalid");
            throw new CustomException("Refresh token has expired or is invalid", HttpStatus.UNAUTHORIZED);
        }

        String newAccessToken = jwtService.generateToken(email);
        String newRefreshToken = jwtService.generateRefreshToken(email);
        log.info("Generated new access token: {}", newAccessToken);

        oldSession.setIsValid(false);
        oldSession.setUpdatedAt(LocalDateTime.now());
        sessionRepository.save(oldSession);
        log.info("Invalidated old session for user: {}", email);

        SessionEntity newSession = SessionEntity.builder()
                .user(oldSession.getUser())
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .isValid(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        sessionRepository.save(newSession);
        log.info("Created new session for user: {}", email);

        UserDetails userDetails = userDetailsService.loadUserByUsername(email);
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);
        log.info("Updated SecurityContextHolder for user: {}", email);

        UsersEntity user = oldSession.getUser();

        AuthUserResponseDTO response = new AuthUserResponseDTO(
                newAccessToken,
                newRefreshToken,
                user.getEmail(),
                user.getUsername(),
                user.getRole().getName()
        );

        log.info("Refresh token successful for user: {}", email);
        return ResponseEntity.ok(response);
    }

    public ResponseEntity<String> registerUser(AuthUserRequestDTO userRequest) {
        if (userRequest == null || userRequest.getEmail() == null || userRequest.getUsername() == null) {
            return ResponseEntity.badRequest().body("Missing required user data");
        }

        if (userRepository.findByEmail(userRequest.getEmail()).isPresent() ||
                userRepository.findByUsername(userRequest.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Email or Username already exists!");
        }

        RoleEntity userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new RuntimeException("Role USER not found"));

        UsersEntity user = createUserEntity(userRequest, userRole);
        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully!");
    }

    public ResponseEntity<String> updatePassword(AuthUserRequestDTO userRequest) {
        if (userRequest == null || userRequest.getEmail() == null ||
                userRequest.getPassword() == null || userRequest.getPassword().isBlank()) {
            return ResponseEntity.badRequest().body("Invalid request data");
        }

        UsersEntity user = userRepository.findByEmail(userRequest.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setPassword(passwordEncoder.encode(userRequest.getPassword()));
        userRepository.save(user);

        return ResponseEntity.ok("Password updated successfully!");
    }

    public ResponseEntity<String> registerAdmin(AuthUserRequestDTO userRequest) {
        if (userRequest == null || userRequest.getEmail() == null || userRequest.getUsername() == null) {
            return ResponseEntity.badRequest().body("Missing required admin data");
        }

        if (userRepository.findByEmail(userRequest.getEmail()).isPresent() ||
                userRepository.findByUsername(userRequest.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Email or Username already exists!");
        }

        RoleEntity adminRole = roleRepository.findByName("ADMIN")
                .orElseThrow(() -> new RuntimeException("Role ADMIN not found"));

        UsersEntity admin = createUserEntity(userRequest, adminRole);
        userRepository.save(admin);

        return ResponseEntity.ok("Admin registered successfully!");
    }

    public UsersEntity createUserEntity(AuthUserRequestDTO userRequest, RoleEntity role) {
        return dtoToEntityMapper.toUserEntity(userRequest, role, passwordEncoder);
    }

    public boolean userExists(String email) {
        return email != null && userRepository.findByEmail(email).isPresent();
    }
}