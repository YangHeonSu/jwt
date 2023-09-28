package com.spring.jwt.user;

import jakarta.persistence.*;
import lombok.*;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "USER_MANAGEMENT")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "ID")
    private int id;
    @Column(name = "USER_ID")
    private String userId;
    @Column(name = "PASSWORD")
    private String password;
    @Column(name = "NAME")
    private String name;
    @Column(name = "AUTH")
    private String auth;

    @Builder
    public User(String userId, String password ,String name, String auth){
        this.userId = userId;
        this.password = password;
        this.name = name;
        this.auth = auth;
    }
}
