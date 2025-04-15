package com.example.cloudbalance.mapper.accountmanagement;

import com.example.cloudbalance.dto.account.AccountRequestDTO;
import com.example.cloudbalance.dto.account.AccountResponseDTO;
import com.example.cloudbalance.entity.auth.AccountEntity;
import org.springframework.stereotype.Component;

@Component
public class AccountMapper {
    public AccountResponseDTO toAccountResponseDTO(AccountEntity account) {
        if (account == null) {
            return null;
        }

        AccountResponseDTO dto = new AccountResponseDTO();
        dto.setId(account.getId());
        dto.setAccountName(account.getAccountName()); // ✅ Correct getter
        dto.setAccountID(account.getAccountID());
        dto.setArn(account.getArn());
        dto.setRegion(account.getRegion());
        return dto;
    }

    public AccountEntity toAccountEntity(AccountRequestDTO accountRequestDTO) {
        if (accountRequestDTO == null) {
            return null;
        }

        AccountEntity account = new AccountEntity();
        account.setAccountID(accountRequestDTO.getAccountID());
        account.setArn(accountRequestDTO.getArn());
        account.setRegion(accountRequestDTO.getRegion());
        account.setAccountName(accountRequestDTO.getAccountName());
        return account;
    }
}