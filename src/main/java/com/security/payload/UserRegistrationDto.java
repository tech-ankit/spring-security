package com.security.payload;

public record UserRegistrationDto (
        String userName,
        String userMobileNo,
        String userEmail,
        String userPassword,
        String userRole
){ }
