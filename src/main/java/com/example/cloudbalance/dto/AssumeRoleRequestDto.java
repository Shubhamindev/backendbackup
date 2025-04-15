package com.example.cloudbalance.dto;

public class AssumeRoleRequestDto {
    private String roleArn;
    public String getRoleArn() {
        return roleArn;
    }
    public void setRoleArn(String roleArn) {
        this.roleArn = roleArn;
    }
}