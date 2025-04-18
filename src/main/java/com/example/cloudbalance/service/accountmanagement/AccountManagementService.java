package com.example.cloudbalance.service.accountmanagement;

import com.example.cloudbalance.dto.account.AccountRequestDTO;
import com.example.cloudbalance.dto.account.AccountResponseDTO;
import com.example.cloudbalance.entity.auth.AccountEntity;
import com.example.cloudbalance.exception.CustomException;
import com.example.cloudbalance.mapper.accountmanagement.AccountMapper;
import com.example.cloudbalance.repository.AccountRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@Transactional
public class AccountManagementService implements AccountManagementServiceInterface {

    private final AccountRepository accountRepository;
    private final AccountMapper accountMapper;

    public AccountManagementService(AccountRepository accountRepository, AccountMapper accountMapper) {
        this.accountRepository = accountRepository;
        this.accountMapper = accountMapper;
    }

    @Override
    public ResponseEntity<List<AccountResponseDTO>> getAllAccounts() {
        log.info("Fetching all accounts...");
        List<AccountEntity> accounts = accountRepository.findAll();

        if (accounts.isEmpty()) {
            log.warn("No accounts found.");
            throw new CustomException("No accounts found!", HttpStatus.NOT_FOUND);
        }

        List<AccountResponseDTO> accountResponseDTOs = accounts.stream()
                .map(accountMapper::toAccountResponseDTO)
                .collect(Collectors.toList());

        log.info("Successfully fetched {} accounts.", accountResponseDTOs.size());
        return ResponseEntity.ok(accountResponseDTOs);
    }

    @Override
    public ResponseEntity<AccountResponseDTO> getAccountById(Long accountId) {
        log.info("Fetching account with ID: {}", accountId);

        if (accountId == null) {
            log.error("Account ID is null.");
            throw new CustomException("Account ID cannot be null!", HttpStatus.BAD_REQUEST);
        }

        AccountEntity account = accountRepository.findById(accountId)
                .orElseThrow(() -> {
                    log.warn("Account not found with ID: {}", accountId);
                    return new CustomException("Account not found!", HttpStatus.NOT_FOUND);
                });

        log.info("Successfully fetched account with ID: {}", accountId);
        return ResponseEntity.ok(accountMapper.toAccountResponseDTO(account));
    }

    @Override
    public ResponseEntity<String> createAccount(AccountRequestDTO accountRequestDTO) {
        log.info("Creating new account with data: {}", accountRequestDTO);

        if (accountRequestDTO == null) {
            log.error("Account request body is null.");
            throw new CustomException("Request body cannot be null!", HttpStatus.BAD_REQUEST);
        }

        if (accountRequestDTO.getAccountName() == null || accountRequestDTO.getAccountName().isBlank()) {
            log.error("Account name is blank.");
            throw new CustomException("Account name must not be blank!", HttpStatus.BAD_REQUEST);
        }

        if (accountRequestDTO.getAccountID() == null || accountRequestDTO.getAccountID().isBlank()) {
            log.error("Account ID is blank.");
            throw new CustomException("Account ID must not be blank!", HttpStatus.BAD_REQUEST);
        }

        if (accountRequestDTO.getArn() == null || accountRequestDTO.getArn().isBlank()) {
            log.error("ARN is blank.");
            throw new CustomException("ARN must not be blank!", HttpStatus.BAD_REQUEST);
        }

        if (accountRequestDTO.getRegion() == null || accountRequestDTO.getRegion().isBlank()) {
            log.error("Region is blank.");
            throw new CustomException("Region must not be blank!", HttpStatus.BAD_REQUEST);
        }

        if (accountRepository.findByAccountName(accountRequestDTO.getAccountName()).isPresent()) {
            log.warn("Duplicate account name: {}", accountRequestDTO.getAccountName());
            throw new CustomException("Account name already exists!",HttpStatus.CONFLICT);
        }

        if (accountRepository.findByAccountID(accountRequestDTO.getAccountID()).isPresent()) {
            log.warn("Duplicate account ID: {}", accountRequestDTO.getAccountID());
            throw new CustomException("Account ID already exists!", HttpStatus.CONFLICT);
        }

        try {
            AccountEntity newAccount = accountMapper.toAccountEntity(accountRequestDTO);
            accountRepository.save(newAccount);
            log.info("Account created successfully with name: {}", newAccount.getAccountName());
            return ResponseEntity.status(HttpStatus.CREATED).body("Account created successfully!");
        } catch (Exception e) {
            log.error("Failed to create account: {}", e.getMessage(), e);
            throw new CustomException("Failed to create account: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public ResponseEntity<String> updateAccount(Long accountId, AccountRequestDTO accountRequestDTO) {
        log.info("Updating account with ID: {}", accountId);

        if (accountId == null) {
            log.error("Account ID is null.");
            throw new CustomException("Account ID cannot be null!", HttpStatus.BAD_REQUEST);
        }

        AccountEntity account = accountRepository.findById(accountId)
                .orElseThrow(() -> {
                    log.warn("Account not found for update with ID: {}", accountId);
                    return new CustomException("Account not found!", HttpStatus.NOT_FOUND);
                });

        if (accountRequestDTO == null) {
            log.error("Account request body is null.");
            throw new CustomException("Request body cannot be null!", HttpStatus.BAD_REQUEST);
        }

        if (accountRequestDTO.getAccountName() != null && !accountRequestDTO.getAccountName().isBlank()) {
            log.debug("Updating account name to: {}", accountRequestDTO.getAccountName());
            account.setAccountName(accountRequestDTO.getAccountName());
        }

        if (accountRequestDTO.getAccountID() != null && !accountRequestDTO.getAccountID().isBlank()) {
            try {
                Long.parseLong(accountRequestDTO.getAccountID()); // Just for format validation
                log.debug("Updating account ID to: {}", accountRequestDTO.getAccountID());
                account.setAccountID(accountRequestDTO.getAccountID());
            } catch (NumberFormatException e) {
                log.error("Invalid format for Account ID: {}", accountRequestDTO.getAccountID());
                throw new CustomException("Invalid Account ID format!", HttpStatus.BAD_REQUEST);
            }
        }

        if (accountRequestDTO.getArn() != null && !accountRequestDTO.getArn().isBlank()) {
            log.debug("Updating ARN to: {}", accountRequestDTO.getArn());
            account.setArn(accountRequestDTO.getArn());
        }

        if (accountRequestDTO.getRegion() != null && !accountRequestDTO.getRegion().isBlank()) {
            log.debug("Updating region to: {}", accountRequestDTO.getRegion());
            account.setRegion(accountRequestDTO.getRegion());
        }

        try {
            accountRepository.save(account);
            log.info("Account with ID {} updated successfully.", accountId);
            return ResponseEntity.ok("Account updated successfully!");
        } catch (Exception e) {
            log.error("Failed to update account with ID {}: {}", accountId, e.getMessage(), e);
            throw new CustomException("Failed to update account: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public ResponseEntity<String> deleteAccount(Long accountId) {
        log.info("Deleting account with ID: {}", accountId);

        if (accountId == null) {
            log.error("Account ID is null.");
            throw new CustomException("Account ID cannot be null!", HttpStatus.BAD_REQUEST);
        }

        AccountEntity account = accountRepository.findById(accountId)
                .orElseThrow(() -> {
                    log.warn("Account not found for deletion with ID: {}", accountId);
                    return new CustomException("Account not found!", HttpStatus.NOT_FOUND);
                });

        try {
            accountRepository.delete(account);
            log.info("Account with ID {} deleted successfully.", accountId);
            return ResponseEntity.ok("Account deleted successfully!");
        } catch (Exception e) {
            log.error("Failed to delete account with ID {}: {}", accountId, e.getMessage(), e);
            throw new CustomException("Failed to delete account: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
