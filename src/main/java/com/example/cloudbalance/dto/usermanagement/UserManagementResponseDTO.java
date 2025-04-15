package com.example.cloudbalance.dto.usermanagement;

import com.example.cloudbalance.dto.account.AccountResponseDTO; // Ensure this import is present
import lombok.*;

import java.time.LocalDateTime;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserManagementResponseDTO {
    private Long userId;  // Make sure this matches the @Mapping target
    private String username;
    private String email;
    private String role;
    private LocalDateTime lastLogin;
    private Set<AccountResponseDTO> accounts;
}