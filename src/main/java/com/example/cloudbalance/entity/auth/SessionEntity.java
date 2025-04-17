package com.example.cloudbalance.entity.auth;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.Set;

@Entity
@Table(name = "sessions")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SessionEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "access_token", nullable = false, unique = true)
    private String accessToken;

    @Column(name = "refresh_token", nullable = false, unique = true)
    private String refreshToken;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;


    @Column(name = "is_valid", nullable = false)
    private Boolean isValid;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private UsersEntity user;
}