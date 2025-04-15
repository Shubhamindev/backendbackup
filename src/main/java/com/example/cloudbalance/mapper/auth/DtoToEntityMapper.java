package com.example.cloudbalance.util;

import com.example.cloudbalance.dto.authdto.AuthUserRequestDTO;
import com.example.cloudbalance.entity.auth.RoleEntity;
import com.example.cloudbalance.entity.auth.UsersEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DtoToEntityMapper {

    public UsersEntity toUserEntity(AuthUserRequestDTO userRequest, RoleEntity userRole, PasswordEncoder passwordEncoder) {
        UsersEntity user = new UsersEntity();
        user.setEmail(userRequest.getEmail());
        user.setUsername(userRequest.getUsername());
        user.setPassword(passwordEncoder.encode(userRequest.getPassword()));
        user.setRole(userRole);
        return user;
    }
}