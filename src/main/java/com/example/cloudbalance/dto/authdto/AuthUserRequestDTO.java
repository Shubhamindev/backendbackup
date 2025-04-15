package com.example.cloudbalance.dto.authdto;

import jakarta.validation.constraints.Email;
import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthUserRequestDTO {
    @Email(message = "Invalid email format")
    private String email;
    private String username;
    private String password;
}