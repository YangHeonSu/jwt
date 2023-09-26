package com.spring.jwt.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@AllArgsConstructor
@Builder
public class UserDTO {

    private String id;
    private String userId;
    private String password;
    private String name;
    private String auth;


    public void bCryptPasswordEncoder(String bCryptPasswordEncoder) {
        this.password = bCryptPasswordEncoder;
    }
}
