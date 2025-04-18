package com.example.cloudbalance.config.authconfig;

import com.example.cloudbalance.mapper.auth.DtoToEntityMapper;
import com.example.cloudbalance.repository.RoleRepository;
import com.example.cloudbalance.repository.SessionRepository;
import com.example.cloudbalance.repository.UserRepository;
import com.example.cloudbalance.service.authservice.AuthService;
import com.example.cloudbalance.service.authservice.CustomUserDetailsService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;
    private final DtoToEntityMapper dtoToEntityMapper;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter, UserRepository userRepository,
                          SessionRepository sessionRepository, RoleRepository roleRepository,
                          JwtService jwtService, DtoToEntityMapper dtoToEntityMapper) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.roleRepository = roleRepository;
        this.jwtService = jwtService;
        this.dtoToEntityMapper = dtoToEntityMapper;
    }
// this bean is for how user data loaded during authentication
    @Bean
    public UserDetailsService userDetailsService() {
        log.info("Initializing CustomUserDetailsService");
        return new CustomUserDetailsService(userRepository);
    }
// this bean is for how spring security handle http requests
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("Configuring SecurityFilterChain");
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configure(http))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(customAuthEntryPoint())
                        .accessDeniedHandler(customAccessDeniedHandler())
                )
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    //how authentication processed

    @Bean
    public AuthenticationProvider authenticationProvider() {
        log.info("Configuring DaoAuthenticationProvider");
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        log.info("Creating AuthenticationManager");
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        log.info("Initializing BCryptPasswordEncoder");
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationEntryPoint customAuthEntryPoint() {
        return (request, response, ex) -> {
            log.warn("Unauthorized access attempt to {}", request.getRequestURI());
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("timestamp", LocalDateTime.now());
            body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
            body.put("error", "Unauthorized");
            body.put("message", ex.getMessage());
            body.put("path", request.getRequestURI());

            response.getWriter().write(convertObjectToJson(body));
        };
    }

    @Bean
    public AccessDeniedHandler customAccessDeniedHandler() {
        return (request, response, ex) -> {
            log.warn("Access denied to {} - {}", request.getRequestURI(), ex.getMessage());
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("timestamp", LocalDateTime.now());
            body.put("status", HttpServletResponse.SC_FORBIDDEN);
            body.put("error", "Forbidden");
            body.put("message", ex.getMessage());
            body.put("path", request.getRequestURI());

            response.getWriter().write(convertObjectToJson(body));
        };
    }

    private String convertObjectToJson(Map<String, Object> object) throws IOException {
        return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(object);
    }
//having problems with annotation of service thats why i implemented this bean costom injection
    @Bean
    public AuthService authService(UserRepository userRepository, SessionRepository sessionRepository,
                                   RoleRepository roleRepository, JwtService jwtService,
                                   AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder,
                                   DtoToEntityMapper dtoToEntityMapper, UserDetailsService userDetailsService) {
        log.info("Creating AuthService bean");
        return new AuthService(userRepository, sessionRepository, roleRepository, jwtService,
                authenticationManager, passwordEncoder, dtoToEntityMapper, userDetailsService);
    }


}