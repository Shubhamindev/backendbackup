package com.example.cloudbalance.dto.account;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccountRequestDTO {
    @NotBlank(message = "Account name cannot be blank")
    private String accountName;

    @NotBlank(message = "Account ID cannot be blank")
    private String accountID;

    @NotBlank(message = "ARN cannot be blank")
    private String arn;

    @NotBlank(message = "Region cannot be blank")
    private String region;
}