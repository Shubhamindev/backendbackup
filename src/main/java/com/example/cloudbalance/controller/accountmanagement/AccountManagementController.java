package com.example.cloudbalance.controller.accountmanagement;

import com.example.cloudbalance.dto.account.AccountRequestDTO;
import com.example.cloudbalance.dto.account.AccountResponseDTO;
import com.example.cloudbalance.service.accountmanagement.AccountManagementServiceInterface;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/accounts")
@CrossOrigin(origins = "http://localhost:5173")
public class AccountManagementController {
    private final AccountManagementServiceInterface accountManagementService;

    public AccountManagementController(AccountManagementServiceInterface accountManagementService) {
        this.accountManagementService = accountManagementService;
    }

    @GetMapping
    @PreAuthorize("hasAnyAuthority('ADMIN', 'READ-ONLY')")
    public ResponseEntity<List<AccountResponseDTO>> getAllAccounts() {
        return accountManagementService.getAllAccounts();
    }

    @GetMapping("/{accountId}")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'READ-ONLY')")
    public ResponseEntity<AccountResponseDTO> getAccountById(@Valid @PathVariable Long accountId) {
        return accountManagementService.getAccountById(accountId);
    }

    @PostMapping("/create")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<String> createAccount(@Valid @RequestBody AccountRequestDTO accountRequestDTO) {
        return accountManagementService.createAccount(accountRequestDTO);
    }

    @PutMapping("/{accountId}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<String> updateAccount(@Valid @PathVariable Long accountId, @RequestBody AccountRequestDTO accountRequestDTO) {
        return accountManagementService.updateAccount(accountId, accountRequestDTO);
    }

    @DeleteMapping("/{accountId}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<String> deleteAccount( @Valid @PathVariable Long accountId) {
        return accountManagementService.deleteAccount(accountId);
    }
}