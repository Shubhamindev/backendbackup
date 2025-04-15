package com.example.cloudbalance.repository;

import com.example.cloudbalance.entity.auth.UsersEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UsersEntity, Long> {
    Optional<UsersEntity> findByEmail(String email);
    Optional<UsersEntity> findByUsername(String username);
    @Query("SELECT DISTINCT u FROM UsersEntity u LEFT JOIN FETCH u.accounts WHERE u.id = :id")
    Optional<UsersEntity> findByIdWithAccounts(@Param("id") Long id);

}
