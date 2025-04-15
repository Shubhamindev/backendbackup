package com.example.cloudbalance.controller.usermanagement;

import com.example.cloudbalance.dto.usermanagement.UserManagementRequestDTO;
import com.example.cloudbalance.dto.usermanagement.UserManagementResponseDTO;
import com.example.cloudbalance.service.usermanagement.UserManagementServiceInterface;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/usermanagement")
@CrossOrigin(origins = "http://localhost:5173")
public class UserManagementController {
    private final UserManagementServiceInterface userManagementService;

    public UserManagementController(UserManagementServiceInterface userManagementService) {
        this.userManagementService = userManagementService;
    }

    @GetMapping("/users")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'READ-ONLY')")
    public ResponseEntity<List<UserManagementResponseDTO>> getAllUsers() {
        return userManagementService.getAllUsers();
    }

//    @GetMapping("/users/{id}")
//    @PreAuthorize("hasAnyAuthority('ADMIN', 'READONLY')")
//    public ResponseEntity<UserManagementResponseDTO> getUser ById(@PathVariable Long id) {
//        return userManagementService.getUser ById(id);
//    }

    @GetMapping("/users/{id}")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'READ-ONLY')")
    public ResponseEntity<UserManagementResponseDTO> getUserById(@Valid @PathVariable Long id) {
        return userManagementService.getUserById(id);
    }

    @PostMapping("/create")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<String> createUser (@Valid @RequestBody UserManagementRequestDTO userRequest) {
        return userManagementService.createUser (userRequest);
    }

    @PutMapping("/edit/{id}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<String> editUser (
            @PathVariable Long id,
            @Valid @RequestBody UserManagementRequestDTO userRequest) {
        return userManagementService.editUser (id, userRequest);
    }

    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<String> deleteUser (@PathVariable Long id) {
        return userManagementService.deleteUser (id);
    }
}