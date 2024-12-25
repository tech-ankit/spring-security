package com.security.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "user_app")
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false)
    private Long id;

    @Column(name = "user_name")
    private String userName;

    @Column(name = "email", unique = true ,nullable = false)
    private String email;

    @Column(name = "password" , nullable = false , length = 1000)
    private String password;

    @Column(name = "mobile" , length = 10)
    private String mobile;

    @Column(name = "roles" , nullable = false , length = 20)
    private String role;
}
