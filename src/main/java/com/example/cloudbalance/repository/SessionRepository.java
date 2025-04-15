package com.example.cloudbalance.repository;

import com.example.cloudbalance.entity.auth.SessionEntity;
import com.example.cloudbalance.entity.auth.UsersEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SessionRepository extends JpaRepository<SessionEntity, Long> {
    Optional<SessionEntity> findByAccessToken(String accessToken);
    Optional<SessionEntity> findByRefreshToken(String refreshToken);
    List<SessionEntity> findByUserAndIsValid(UsersEntity user, Boolean isValid);

    Optional<SessionEntity> findByRefreshTokenAndIsValid(String refreshToken, boolean b);
}