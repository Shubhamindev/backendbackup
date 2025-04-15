package com.example.cloudbalance.service.usermanagement;

import com.example.cloudbalance.dto.usermanagement.UserManagementRequestDTO;
import com.example.cloudbalance.dto.usermanagement.UserManagementResponseDTO;
import com.example.cloudbalance.entity.auth.AccountEntity;
import com.example.cloudbalance.entity.auth.RoleEntity;
import com.example.cloudbalance.entity.auth.UsersEntity;
import com.example.cloudbalance.globalexceptionhandler.CustomException;
import com.example.cloudbalance.mapper.usermanagement.UserMapper;
import com.example.cloudbalance.repository.AccountRepository;
import com.example.cloudbalance.repository.RoleRepository;
import com.example.cloudbalance.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


@Slf4j
@Service
@Transactional
public class UserManagementService implements UserManagementServiceInterface {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

    public UserManagementService(UserRepository userRepository, RoleRepository roleRepository,
                                 AccountRepository accountRepository, PasswordEncoder passwordEncoder,
                                 UserMapper userMapper) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.accountRepository = accountRepository;
        this.passwordEncoder = passwordEncoder;
        this.userMapper = userMapper;
    }

    @Override
    public ResponseEntity<List<UserManagementResponseDTO>> getAllUsers() {
        List<UsersEntity> users = userRepository.findAll();

        if (users == null || users.isEmpty()) {
            throw new CustomException("No users found.", HttpStatus.NOT_FOUND);
        }

        List<UserManagementResponseDTO> userDTOs = users.stream()
                .map(user -> {
                    try {
                        return userMapper.toUserManagementResponseDTO(user);
                    } catch (Exception e) {
                        throw new CustomException("Error mapping user data.", HttpStatus.INTERNAL_SERVER_ERROR);
                    }
                })
                .collect(Collectors.toList());
        log.info( "Fetched all users successfully.");
        return ResponseEntity.ok(userDTOs);
    }



    public ResponseEntity<UserManagementResponseDTO> getUserById(Long id) {
        if (id == null) {
            throw new CustomException("User ID cannot be null.", HttpStatus.BAD_REQUEST);
        }

        UsersEntity user = userRepository.findByIdWithAccounts(id)
                .orElseThrow(() -> new CustomException("User not found.", HttpStatus.NOT_FOUND));

        return ResponseEntity.ok(userMapper.toUserManagementResponseDTO(user));
    }

    @Override
    public ResponseEntity<String> createUser(UserManagementRequestDTO userRequest) {
        if (userRequest == null) {
            throw new CustomException("Request cannot be null.", HttpStatus.BAD_REQUEST);
        }

        if (userRequest.getEmail() == null || userRequest.getEmail().isEmpty()) {
            throw new CustomException("Email is required.", HttpStatus.BAD_REQUEST);
        }

        if (userRequest.getUsername() == null || userRequest.getUsername().isEmpty()) {
            throw new CustomException("Username is required.", HttpStatus.BAD_REQUEST);
        }

        if (userRequest.getPassword() == null || userRequest.getPassword().isEmpty()) {
            throw new CustomException("Password is required.", HttpStatus.BAD_REQUEST);
        }

        if (userRepository.findByEmail(userRequest.getEmail()).isPresent()) {
            throw new CustomException("Email already exists!", HttpStatus.BAD_REQUEST);
        }

        if (userRepository.findByUsername(userRequest.getUsername()).isPresent()) {
            throw new CustomException("Username already exists!", HttpStatus.BAD_REQUEST);
        }

        RoleEntity role = roleRepository.findByName(userRequest.getRole())
                .orElseThrow(() -> new CustomException("Role not found!", HttpStatus.NOT_FOUND));

        UsersEntity newUser = UsersEntity.builder()
                .email(userRequest.getEmail())
                .username(userRequest.getUsername())
                .password(passwordEncoder.encode(userRequest.getPassword()))
                .role(role)
                .build();

        if (userRequest.getAccountIds() != null && !userRequest.getAccountIds().isEmpty()) {
            if (!"CUSTOMER".equalsIgnoreCase(userRequest.getRole())) {
                throw new CustomException(
                        "Accounts can only be assigned to users with the CUSTOMER role.",
                        HttpStatus.FORBIDDEN
                );
            }
            Set<AccountEntity> accounts = accountRepository.findAllByIdIn(userRequest.getAccountIds());
            if (accounts == null || accounts.isEmpty()) {
                throw new CustomException("No accounts found for the provided IDs.", HttpStatus.NOT_FOUND);
            }
            newUser.setAccounts(accounts);
        }

        userRepository.save(newUser);
        log.info("User created successfully with ID: {}", newUser.getId());
        return ResponseEntity.ok("User created successfully!");
    }

    @Override
    public ResponseEntity<String> editUser(Long id, UserManagementRequestDTO userRequest) {
        if (id == null || userRequest == null) {
            throw new CustomException("Invalid request.", HttpStatus.BAD_REQUEST);
        }

        UsersEntity user = userRepository.findById(id)
                .orElseThrow(() -> new CustomException("User not found!", HttpStatus.NOT_FOUND));

        // --- Email Update ---
        String newEmail = userRequest.getEmail();
        if (newEmail != null && !newEmail.isBlank()) {
            if (!user.getEmail().equals(newEmail) &&
                    userRepository.findByEmail(newEmail).isPresent()) {
                throw new CustomException("Email already exists!", HttpStatus.BAD_REQUEST);
            }
            user.setEmail(newEmail);
        }

        // --- Username Update ---
        String newUsername = userRequest.getUsername();
        if (newUsername != null && !newUsername.isBlank()) {
            if (!user.getUsername().equals(newUsername) &&
                    userRepository.findByUsername(newUsername).isPresent()) {
                throw new CustomException("Username already exists!", HttpStatus.BAD_REQUEST);
            }
            user.setUsername(newUsername);
        }

        // --- Password Update ---
        String newPassword = userRequest.getPassword();
        if (newPassword != null && !newPassword.isBlank()) {
            user.setPassword(passwordEncoder.encode(newPassword));
        }

        // --- Role Update ---
        String newRole = userRequest.getRole();
        if (newRole != null && !newRole.isBlank()) {
            RoleEntity roleEntity = roleRepository.findByName(newRole)
                    .orElseThrow(() -> new CustomException("Role not found!", HttpStatus.NOT_FOUND));
            user.setRole(roleEntity);
        }

        // --- Final Role after update ---
        String updatedRole = user.getRole().getName();

        // --- Validation: Reject accountIds for non-CUSTOMER roles ---
        if (!"CUSTOMER".equalsIgnoreCase(updatedRole)
                && userRequest.getAccountIds() != null
                && !userRequest.getAccountIds().isEmpty()) {
            throw new CustomException("Accounts can only be assigned to users with the CUSTOMER role.", HttpStatus.FORBIDDEN);
        }

        // --- Account Assignment ---
        if ("CUSTOMER".equalsIgnoreCase(updatedRole)) {
            Set<AccountEntity> accounts = accountRepository.findAllByIdIn(
                    userRequest.getAccountIds() != null ? userRequest.getAccountIds() : Collections.emptySet()
            );
            user.setAccounts(accounts);
        } else {
            user.setAccounts(Collections.emptySet()); // Always clear for non-CUSTOMER roles
        }

        userRepository.save(user);
        log.info("User updated successfully with ID: {}", user.getId());
        return ResponseEntity.ok("User updated successfully!");
    }


    @Override
    public ResponseEntity<String> deleteUser(Long id) {
        if (id == null) {
            throw new CustomException("User ID cannot be null.", HttpStatus.BAD_REQUEST);
        }

        UsersEntity user = userRepository.findById(id)
                .orElseThrow(() -> new CustomException("User not found!", HttpStatus.NOT_FOUND));

        user.getAccounts().clear(); // in case of constraint errors
        userRepository.delete(user);

        return ResponseEntity.ok("User deleted successfully!");
    }
}