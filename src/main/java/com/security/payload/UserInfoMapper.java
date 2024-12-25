package com.security.payload;

import com.security.entity.AppUser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * @author atquil
 */
@Component
@RequiredArgsConstructor
public class UserInfoMapper {

    private final PasswordEncoder passwordEncoder;
    public AppUser convertToEntity(UserRegistrationDto userRegistrationDto) {
        AppUser userInfoEntity = new AppUser();
        userInfoEntity.setUserName(userRegistrationDto.userName());
        userInfoEntity.setEmail(userRegistrationDto.userEmail());
        userInfoEntity.setMobile(userRegistrationDto.userMobileNo());
        userInfoEntity.setRole(userRegistrationDto.userRole());
        userInfoEntity.setPassword(passwordEncoder.encode(userRegistrationDto.userPassword()));
        return userInfoEntity;
    }
}

