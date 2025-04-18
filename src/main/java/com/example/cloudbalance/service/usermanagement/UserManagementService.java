package com.example.cloudbalance.service.usermanagement;

import com.example.cloudbalance.dto.usermanagement.UserManagementRequestDTO;
import com.example.cloudbalance.dto.usermanagement.UserManagementResponseDTO;
import com.example.cloudbalance.entity.auth.AccountEntity;
import com.example.cloudbalance.entity.auth.RoleEntity;
import com.example.cloudbalance.entity.auth.UsersEntity;
import com.example.cloudbalance.exception.CustomException;
import com.example.cloudbalance.mapper.usermanagement.UserMapper;
import com.example.cloudbalance.repository.AccountRepository;
import com.example.cloudbalance.repository.RoleRepository;
import com.example.cloudbalance.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
        log.info("Fetching all users...");
        List<UsersEntity> users = userRepository.findAll();

        if (users.isEmpty()) {
            log.warn("No users found in the database.");
            throw new CustomException("No users found.", HttpStatus.NOT_FOUND);
        }

        List<UserManagementResponseDTO> userDTOs = users.stream()
                .map(user -> {
                    try {
                        return userMapper.toUserManagementResponseDTO(user);
                    } catch (Exception e) {
                        log.error("Error mapping user entity to DTO for user: {}", user.getId(), e);
                        throw new CustomException("Error mapping user data.", HttpStatus.INTERNAL_SERVER_ERROR);
                    }
                })
                .collect(Collectors.toList());

        log.info("Fetched {} users successfully.", userDTOs.size());
        return ResponseEntity.ok(userDTOs);
    }

    public ResponseEntity<UserManagementResponseDTO> getUserById(Long id) {
        log.info("Fetching user by ID: {}", id);
        if (id == null) {
            log.warn("User ID is null.");
            throw new CustomException("User ID cannot be null.", HttpStatus.BAD_REQUEST);
        }

        UsersEntity user = userRepository.findByIdWithAccounts(id)
                .orElseThrow(() -> {
                    log.warn("User not found with ID: {}", id);
                    return new CustomException("User not found.", HttpStatus.NOT_FOUND);
                });

        log.info("User fetched successfully: ID {}", user.getId());
        return ResponseEntity.ok(userMapper.toUserManagementResponseDTO(user));
    }

    @Override
    public ResponseEntity<String> createUser(UserManagementRequestDTO userRequest) {
        log.info("Creating new user: {}", userRequest.getUsername());

        if (userRequest.getEmail() == null || userRequest.getEmail().isEmpty()) {
            log.warn("Email is missing in request.");
            throw new CustomException("Email is required.", HttpStatus.BAD_REQUEST);
        }

        if (userRequest.getUsername() == null || userRequest.getUsername().isEmpty()) {
            log.warn("Username is missing in request.");
            throw new CustomException("Username is required.", HttpStatus.BAD_REQUEST);
        }

        if (userRequest.getPassword() == null || userRequest.getPassword().isEmpty()) {
            log.warn("Password is missing in request.");
            throw new CustomException("Password is required.", HttpStatus.BAD_REQUEST);
        }

        if (userRepository.findByEmail(userRequest.getEmail()).isPresent()) {
            log.warn("Email already exists: {}", userRequest.getEmail());
            throw new CustomException("Email already exists!", HttpStatus.CONFLICT);
        }

        if (userRepository.findByUsername(userRequest.getUsername()).isPresent()) {
            log.warn("Username already exists: {}", userRequest.getUsername());
            throw new CustomException("Username already exists!", HttpStatus.CONFLICT);
        }

        RoleEntity role = roleRepository.findByName(userRequest.getRole())
                .orElseThrow(() -> {
                    log.error("Role not found: {}", userRequest.getRole());
                    return new CustomException("Role not found!", HttpStatus.NOT_FOUND);
                });

        UsersEntity newUser = UsersEntity.builder()
                .email(userRequest.getEmail())
                .username(userRequest.getUsername())
                .password(passwordEncoder.encode(userRequest.getPassword()))
                .role(role)
                .build();

        if (userRequest.getAccountIds() != null && !userRequest.getAccountIds().isEmpty()) {
            if (!"CUSTOMER".equalsIgnoreCase(userRequest.getRole())) {
                log.warn("Non-CUSTOMER role attempted to assign accounts.");
                throw new CustomException("Accounts can only be assigned to users with the CUSTOMER role.", HttpStatus.FORBIDDEN);
            }

            Set<AccountEntity> accounts = accountRepository.findAllByIdIn(userRequest.getAccountIds());
            if (accounts == null || accounts.isEmpty()) {
                log.warn("No accounts found for provided IDs: {}", userRequest.getAccountIds());
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
        log.info("Editing user with ID: {}", id);
        if (id == null || userRequest == null) {
            log.error("Edit request invalid: ID or request body is null.");
            throw new CustomException("Invalid request.", HttpStatus.BAD_REQUEST);
        }

        UsersEntity user = userRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("User not found for edit: ID {}", id);
                    return new CustomException("User not found!", HttpStatus.NOT_FOUND);
                });

        // Email
        String newEmail = userRequest.getEmail();
        if (newEmail != null && !newEmail.isBlank()) {
            if (!user.getEmail().equals(newEmail) &&
                    userRepository.findByEmail(newEmail).isPresent()) {
                log.warn("Email already exists during edit: {}", newEmail);
                throw new CustomException("Email already exists!", HttpStatus.CONFLICT);
            }
            user.setEmail(newEmail);
        }

        // Username
        String newUsername = userRequest.getUsername();
        if (newUsername != null && !newUsername.isBlank()) {
            if (!user.getUsername().equals(newUsername) &&
                    userRepository.findByUsername(newUsername).isPresent()) {
                log.warn("Username already exists during edit: {}", newUsername);
                throw new CustomException("Username already exists!", HttpStatus.CONFLICT);
            }
            user.setUsername(newUsername);
        }

        // Password
        String newPassword = userRequest.getPassword();
        if (newPassword != null && !newPassword.isBlank()) {
            user.setPassword(passwordEncoder.encode(newPassword));
        }

        // Role
        String newRole = userRequest.getRole();
        if (newRole != null && !newRole.isBlank()) {
            RoleEntity roleEntity = roleRepository.findByName(newRole)
                    .orElseThrow(() -> {
                        log.error("Role not found during update: {}", newRole);
                        return new CustomException("Role not found!", HttpStatus.NOT_FOUND);
                    });
            user.setRole(roleEntity);
        }

        String updatedRole = user.getRole().getName();

        // Account validation for non-CUSTOMER roles
        if (!"CUSTOMER".equalsIgnoreCase(updatedRole)
                && userRequest.getAccountIds() != null
                && !userRequest.getAccountIds().isEmpty()) {
            log.warn("Non-CUSTOMER user cannot have account associations.");
            throw new CustomException("Accounts can only be assigned to users with the CUSTOMER role.", HttpStatus.FORBIDDEN);
        }

        // Accounts for CUSTOMER role
        if ("CUSTOMER".equalsIgnoreCase(updatedRole)) {
            Set<AccountEntity> accounts = accountRepository.findAllByIdIn(
                    userRequest.getAccountIds() != null ? userRequest.getAccountIds() : Collections.emptySet()
            );
            user.setAccounts(accounts);
        } else {
            user.setAccounts(Collections.emptySet());
        }

        userRepository.save(user);
        log.info("User updated successfully with ID: {}", user.getId());
        return ResponseEntity.ok("User updated successfully!");
    }

    @Override
    public ResponseEntity<String> deleteUser(Long id) {
        log.info("Deleting user with ID: {}", id);
        if (id == null) {
            log.warn("Delete request failed: user ID is null.");
            throw new CustomException("User ID cannot be null.", HttpStatus.BAD_REQUEST);
        }

        UsersEntity user = userRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("User not found during delete: ID {}", id);
                    return new CustomException("User not found!", HttpStatus.NOT_FOUND);
                });

        user.getAccounts().clear(); // to avoid constraint issues
        userRepository.delete(user);

        log.info("User deleted successfully: ID {}", id);
        return ResponseEntity.ok("User deleted successfully!");
    }
}
