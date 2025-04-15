package com.example.cloudbalance.service.accountmanagement;

import com.example.cloudbalance.dto.account.AccountRequestDTO;
import com.example.cloudbalance.dto.account.AccountResponseDTO;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface AccountManagementServiceInterface {
    ResponseEntity<List<AccountResponseDTO>> getAllAccounts();
    ResponseEntity<AccountResponseDTO> getAccountById(Long accountId);
    ResponseEntity<String> createAccount(AccountRequestDTO accountRequest);
    ResponseEntity<String> updateAccount(Long accountId, AccountRequestDTO accountRequest);
    ResponseEntity<String> deleteAccount(Long accountId);
}