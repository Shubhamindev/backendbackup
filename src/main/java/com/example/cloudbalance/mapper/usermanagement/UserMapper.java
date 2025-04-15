package com.example.cloudbalance.mapper.usermanagement;


import com.example.cloudbalance.dto.account.AccountResponseDTO;
import com.example.cloudbalance.dto.usermanagement.UserManagementResponseDTO;
import com.example.cloudbalance.entity.auth.UsersEntity;
import com.example.cloudbalance.mapper.accountmanagement.AccountMapper;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;


@Component
public class UserMapper {

    private final AccountMapper accountMapper;

    public UserMapper(AccountMapper accountMapper) {
        this.accountMapper = accountMapper;
    }

    public UserManagementResponseDTO toUserManagementResponseDTO(UsersEntity user) {
        if (user == null) {
            return null;
        }

        UserManagementResponseDTO dto = new UserManagementResponseDTO();
        dto.setUserId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setRole(user.getRole().getName());
        dto.setLastLogin(user.getLastLogin());

        if (user.getAccounts() != null) {
            Set<AccountResponseDTO> accountDTOs = user.getAccounts().stream()
                    .map(accountMapper::toAccountResponseDTO)
                    .collect(Collectors.toSet());
            dto.setAccounts(accountDTOs);
        }
        return dto;
    }
}