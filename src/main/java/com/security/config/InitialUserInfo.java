package com.security.config;

import com.security.entity.AppUser;
import com.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;


@RequiredArgsConstructor
@Component
@Slf4j
public class InitialUserInfo implements CommandLineRunner {
    private final UserRepository userInfoRepo;
    private final PasswordEncoder passwordEncoder;
    @Override
    public void run(String... args) throws Exception {
        AppUser manager = new AppUser();
        manager.setUserName("Manager");
        manager.setPassword(passwordEncoder.encode("password"));
        manager.setRole("ROLE_MANAGER");
        manager.setEmail("manager@manager.com");

        AppUser admin = new AppUser();
        admin.setUserName("Admin");
        admin.setPassword(passwordEncoder.encode("password"));
        admin.setRole("ROLE_ADMIN");
        admin.setEmail("admin@admin.com");

        AppUser user = new AppUser();
        user.setUserName("User");
        user.setPassword(passwordEncoder.encode("password"));
        user.setRole("ROLE_USER");
        user.setEmail("user@user.com");

        userInfoRepo.saveAll(List.of(manager,admin,user));
    }

}
