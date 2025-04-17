package com.example.cloudbalance.service.authservice;
import com.example.cloudbalance.dto.authdto.AuthUserRequestDTO;
import com.example.cloudbalance.dto.authdto.AuthUserResponseDTO;
import org.springframework.http.ResponseEntity;


public interface IAuthService {
    ResponseEntity<AuthUserResponseDTO> loginUser(AuthUserRequestDTO userRequest);
    ResponseEntity<String> registerUser(AuthUserRequestDTO userRequest);
    ResponseEntity<String> logoutUser(String token);
    ResponseEntity<AuthUserResponseDTO> refreshToken(String refreshToken);
    ResponseEntity<String> updatePassword(AuthUserRequestDTO userRequest);
    ResponseEntity<String> registerAdmin(AuthUserRequestDTO userRequest);

    boolean userExists(String email);
}
