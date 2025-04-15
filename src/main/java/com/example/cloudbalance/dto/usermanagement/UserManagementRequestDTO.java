package com.example.cloudbalance.dto.usermanagement;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserManagementRequestDTO {
    @Email(message = "Invalid email format")
    private String email;
    private String username;
    @Size(min = 6  , message = "Password must be at least 6 characters")
    private String password;
    private String role;
    private Set<Long> accountIds;
}