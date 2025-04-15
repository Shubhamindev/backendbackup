package com.example.cloudbalance.entity.auth;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

import java.util.Set;

@Entity
@Table(name = "accounts")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccountEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String accountID;

    @Column(nullable = false)
    private String arn;

    @Column(nullable = false)
    private String region;

    @Column(name = "account_name", nullable = false) // Add this line
    private String accountName; // Add this field

    @ManyToMany( fetch = FetchType.EAGER)
    @JsonIgnore
    private Set<UsersEntity> users;


}