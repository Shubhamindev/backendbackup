package com.example.cloudbalance.repository;

import com.example.cloudbalance.entity.auth.AccountEntity;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.Set;

@Repository
public interface AccountRepository extends JpaRepository<AccountEntity, Long> {
    Set<AccountEntity> findAllByIdIn(Set<Long> ids);

    // Find an account by its name
    Optional<AccountEntity> findByAccountName(String accountName);

    Optional<AccountEntity> findByAccountID(@NotBlank(message = "Account ID cannot be blank") String accountID);
}