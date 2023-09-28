package com.spring.jwt.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDTO {

    private String id;
    private String userId;
    private String password;
    private String name;
    private String auth;

    /**
     * 비밀번호 암호화 설정
     * @param bCryptPasswordEncoder String password
     */
    public void bCryptPasswordEncoder(String bCryptPasswordEncoder) {
        this.password = bCryptPasswordEncoder;
    }

    // DTO -> Entity
    public User toEntity() {
        return User.builder()
                .userId(userId)
                .password(password)
                .name(name)
                .auth(auth)
                .build();
    }
}
