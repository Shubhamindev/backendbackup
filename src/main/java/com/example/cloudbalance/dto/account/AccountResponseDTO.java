package com.example.cloudbalance.dto.account;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder

public class AccountResponseDTO {
    private Long id;
    private String accountID;
    private String arn;
    private String region;
    private String accountName;

}