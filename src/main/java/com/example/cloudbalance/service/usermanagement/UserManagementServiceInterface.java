package com.example.cloudbalance.service.usermanagement;

import com.example.cloudbalance.dto.usermanagement.UserManagementRequestDTO;
import com.example.cloudbalance.dto.usermanagement.UserManagementResponseDTO;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface UserManagementServiceInterface {
    ResponseEntity<List<UserManagementResponseDTO>> getAllUsers();
    ResponseEntity<UserManagementResponseDTO> getUserById(Long id); // Fixed naming convention
    ResponseEntity<String> createUser(UserManagementRequestDTO userRequest);
    ResponseEntity<String> editUser(Long id, UserManagementRequestDTO userRequest);
    ResponseEntity<String> deleteUser(Long id);
}