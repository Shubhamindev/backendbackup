package com.example.cloudbalance.service.accountmanagement;

import com.example.cloudbalance.dto.account.AccountRequestDTO;
import com.example.cloudbalance.dto.account.AccountResponseDTO;
import com.example.cloudbalance.entity.auth.AccountEntity;
import com.example.cloudbalance.globalexceptionhandler.CustomException;
import com.example.cloudbalance.mapper.accountmanagement.AccountMapper;
import com.example.cloudbalance.repository.AccountRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

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
        List<AccountEntity> accounts = accountRepository.findAll();

        if (accounts.isEmpty()) {
            throw new CustomException("No accounts found!", HttpStatus.NOT_FOUND);
        }

        List<AccountResponseDTO> accountResponseDTOs = accounts.stream()
                .map(accountMapper::toAccountResponseDTO)
                .collect(Collectors.toList());

        return ResponseEntity.ok(accountResponseDTOs);
    }

    @Override
    public ResponseEntity<AccountResponseDTO> getAccountById(Long accountId) {
        if (accountId == null) {
            throw new CustomException("Account ID cannot be null!", HttpStatus.BAD_REQUEST);
        }

        AccountEntity account = accountRepository.findById(accountId)
                .orElseThrow(() -> new CustomException("Account not found!", HttpStatus.NOT_FOUND));

        AccountResponseDTO accountResponseDTO = accountMapper.toAccountResponseDTO(account);
        return ResponseEntity.ok(accountResponseDTO);
    }

    @Override
    public ResponseEntity<String> createAccount(AccountRequestDTO accountRequestDTO) {
        if (accountRequestDTO == null) {
            throw new CustomException("Request body cannot be null!", HttpStatus.BAD_REQUEST);
        }

        if (accountRequestDTO.getAccountName() == null || accountRequestDTO.getAccountName().isBlank()) {
            throw new CustomException("Account name must not be blank!", HttpStatus.BAD_REQUEST);
        }

        if (accountRequestDTO.getAccountID() == null || accountRequestDTO.getAccountID().isBlank()) {
            throw new CustomException("Account ID must not be blank!", HttpStatus.BAD_REQUEST);
        }

        if (accountRequestDTO.getArn() == null || accountRequestDTO.getArn().isBlank()) {
            throw new CustomException("ARN must not be blank!", HttpStatus.BAD_REQUEST);
        }

        if (accountRequestDTO.getRegion() == null || accountRequestDTO.getRegion().isBlank()) {
            throw new CustomException("Region must not be blank!", HttpStatus.BAD_REQUEST);
        }

        Optional<AccountEntity> existingAccount = accountRepository.findByAccountName(accountRequestDTO.getAccountName());
        if (existingAccount.isPresent()) {
            throw new CustomException("Account name already exists!", HttpStatus.BAD_REQUEST);
        }
        existingAccount = accountRepository.findByAccountID(accountRequestDTO.getAccountID());
        if (existingAccount.isPresent()) {
            throw new CustomException("Account ID already exists!", HttpStatus.BAD_REQUEST);
        }

        try {
            AccountEntity newAccount = accountMapper.toAccountEntity(accountRequestDTO);
            accountRepository.save(newAccount);
            return ResponseEntity.status(HttpStatus.CREATED).body("Account created successfully!");
        } catch (Exception e) {
            throw new CustomException("Failed to create account: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @Override
    public ResponseEntity<String> updateAccount(Long accountId, AccountRequestDTO accountRequestDTO) {
        if (accountId == null) {
            throw new CustomException("Account ID cannot be null!", HttpStatus.BAD_REQUEST);
        }

        AccountEntity account = accountRepository.findById(accountId)
                .orElseThrow(() -> new CustomException("Account not found!", HttpStatus.NOT_FOUND));

        if (accountRequestDTO == null) {
            throw new CustomException("Request body cannot be null!", HttpStatus.BAD_REQUEST);
        }

        if (accountRequestDTO.getAccountName() != null && !accountRequestDTO.getAccountName().isBlank()) {
            account.setAccountName(accountRequestDTO.getAccountName());
        }

        if (accountRequestDTO.getAccountID() != null && !accountRequestDTO.getAccountID().isBlank()) {
            try {
                Long accountID = Long.parseLong(accountRequestDTO.getAccountID());
                account.setAccountID(accountID.toString());
            } catch (NumberFormatException e) {
                throw new CustomException("Invalid Account ID format!", HttpStatus.BAD_REQUEST);
            }
        }

        if (accountRequestDTO.getArn() != null && !accountRequestDTO.getArn().isBlank()) {
            account.setArn(accountRequestDTO.getArn());
        }

        if (accountRequestDTO.getRegion() != null && !accountRequestDTO.getRegion().isBlank()) {
            account.setRegion(accountRequestDTO.getRegion());
        }

        try {
            accountRepository.save(account);
            return ResponseEntity.ok("Account updated successfully!");
        } catch (Exception e) {
            throw new CustomException("Failed to update account: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public ResponseEntity<String> deleteAccount(Long accountId) {
        if (accountId == null) {
            throw new CustomException("Account ID cannot be null!", HttpStatus.BAD_REQUEST);
        }

        AccountEntity account = accountRepository.findById(accountId)
                .orElseThrow(() -> new CustomException("Account not found!", HttpStatus.NOT_FOUND));

        try {
            accountRepository.delete(account);
            return ResponseEntity.ok("Account deleted successfully!");
        } catch (Exception e) {
            throw new CustomException("Failed to delete account: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}